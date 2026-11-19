//! Three-way merge of a JSON, TOML, or YAML mapping by key.
//!
//! Maps merge recursively. Arrays and scalars are atomic. A key one side
//! changed takes that side. A key both sides changed the same way is kept.
//! A key both sides changed differently, or one side deleted while the other
//! edited, is a clash. Rendering edits the local document so its key order
//! and comments survive.

use indexmap::IndexMap;

use super::files::KeyMerge;

#[derive(Clone, Copy)]
pub(super) enum Format {
    Json,
    Toml,
    Yaml,
}

#[derive(Clone)]
enum Node {
    Map(IndexMap<String, Node>),
    Atom(String),
}

#[derive(Clone)]
enum Change {
    Same,
    Set(Node),
    Delete,
}

enum Decision {
    Keep(Node),
    Clash,
}

pub(super) fn merge(
    format: Format,
    mode: String,
    base: &str,
    local_text: &str,
    remote_text: &str,
) -> eyre::Result<Option<KeyMerge>> {
    if [base, local_text, remote_text]
        .iter()
        .any(|text| duplicate_keys(format, text))
    {
        return Ok(Some(KeyMerge::Clash));
    }
    let (Ok(base), Ok(local), Ok(remote)) = (
        parse(format, base),
        parse(format, local_text),
        parse(format, remote_text),
    ) else {
        return Ok(None);
    };
    if local == remote {
        return Ok(Some(KeyMerge::KeepLocal));
    }
    let Decision::Keep(merged) = decide(&base, &local, &remote) else {
        return Ok(Some(KeyMerge::Clash));
    };
    let Ok(text) = render(format, local_text, remote_text, &merged) else {
        return Ok(Some(KeyMerge::Clash));
    };
    Ok(Some(KeyMerge::Merged {
        mode,
        text: text.into_bytes(),
    }))
}

fn parse(format: Format, text: &str) -> Result<Node, ()> {
    match format {
        Format::Json => json::parse(text),
        Format::Toml => toml_doc::parse(text),
        Format::Yaml => yaml_doc::parse(text),
    }
}
fn duplicate_keys(format: Format, text: &str) -> bool {
    match format {
        Format::Json => json::duplicate_keys(text),
        Format::Toml => toml_doc::duplicate_keys(text),
        Format::Yaml => yaml_doc::duplicate_keys(text),
    }
}

fn render(format: Format, local: &str, remote: &str, merged: &Node) -> eyre::Result<String> {
    if parse(format, local).ok().as_ref() == Some(merged) {
        return Ok(local.to_string());
    }
    if matches!(merged, Node::Atom(_)) && parse(format, remote).ok().as_ref() == Some(merged) {
        return Ok(remote.to_string());
    }
    if !matches!(merged, Node::Map(_)) {
        eyre::bail!("a non-map root is kept only as one side's own text");
    }
    let text = match format {
        Format::Json => json::render(local, remote, merged)?,
        Format::Toml => toml_doc::render(local, merged)?,
        Format::Yaml => yaml_doc::render(local, remote, merged)?,
    };
    match parse(format, &text) {
        Ok(parsed) if parsed == *merged => Ok(text),
        _ => eyre::bail!("rendered text does not parse to the decided value"),
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Node::Map(left), Node::Map(right)) => {
                left.len() == right.len()
                    && left
                        .iter()
                        .all(|(key, value)| right.get(key).is_some_and(|other| value == other))
            }
            (Node::Atom(left), Node::Atom(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for Node {}

fn decide(base: &Node, local: &Node, remote: &Node) -> Decision {
    match (base, local, remote) {
        (Node::Map(base), Node::Map(local), Node::Map(remote)) => decide_map(base, local, remote),
        _ if local == remote => Decision::Keep(local.clone()),
        _ if local == base => Decision::Keep(remote.clone()),
        _ if remote == base => Decision::Keep(local.clone()),
        _ => Decision::Clash,
    }
}

fn decide_map(
    base: &IndexMap<String, Node>,
    local: &IndexMap<String, Node>,
    remote: &IndexMap<String, Node>,
) -> Decision {
    let mut keys = local.keys().cloned().collect::<Vec<_>>();
    for key in remote.keys() {
        if !local.contains_key(key) {
            keys.push(key.clone());
        }
    }
    let mut merged = IndexMap::new();
    for key in keys {
        let change = combine(
            base.get(&key),
            side_change(base, local, &key),
            side_change(base, remote, &key),
        );
        match change {
            Some(Change::Same) => {
                if let Some(value) = local.get(&key) {
                    merged.insert(key, value.clone());
                }
            }
            Some(Change::Set(value)) => {
                merged.insert(key, value);
            }
            Some(Change::Delete) => {}
            None => return Decision::Clash,
        }
    }
    Decision::Keep(Node::Map(merged))
}

fn side_change(base: &IndexMap<String, Node>, side: &IndexMap<String, Node>, key: &str) -> Change {
    match (base.get(key), side.get(key)) {
        (Some(before), Some(after)) if before == after => Change::Same,
        (_, Some(after)) => Change::Set(after.clone()),
        (Some(_), None) => Change::Delete,
        (None, None) => Change::Same,
    }
}

fn combine(base: Option<&Node>, local: Change, remote: Change) -> Option<Change> {
    match (local, remote) {
        (Change::Same, other) | (other, Change::Same) => Some(other),
        (Change::Delete, Change::Delete) => Some(Change::Delete),
        (Change::Set(local), Change::Set(remote)) => {
            let Some(base) = base else {
                return (local == remote).then_some(Change::Set(local));
            };
            match decide(base, &local, &remote) {
                Decision::Keep(value) => Some(Change::Set(value)),
                Decision::Clash => None,
            }
        }
        _ => None,
    }
}

mod json {
    use super::Node;
    use serde_json::Value;

    pub(super) fn parse(text: &str) -> Result<Node, ()> {
        let value = serde_json::from_str::<Value>(text).map_err(|_| ())?;
        Ok(from_value(&value))
    }

    fn from_value(value: &Value) -> Node {
        match value {
            Value::Object(map) => Node::Map(
                map.iter()
                    .map(|(key, value)| (key.clone(), from_value(value)))
                    .collect(),
            ),
            other => Node::Atom(canonical(other)),
        }
    }

    pub(super) fn render(local: &str, remote: &str, merged: &Node) -> eyre::Result<String> {
        let local_raw = raw_object(local)?;
        let remote_raw = raw_object(remote)?;
        let indent = indent_of(local);
        let mut text = String::new();
        print_object(&local_raw, &remote_raw, merged, &indent, 0, &mut text)?;
        if local.is_empty() || local.ends_with('\n') {
            text.push('\n');
        }
        Ok(text)
    }

    fn raw_object(
        text: &str,
    ) -> eyre::Result<indexmap::IndexMap<String, Box<serde_json::value::RawValue>>> {
        if text.trim().is_empty() {
            return Ok(indexmap::IndexMap::new());
        }
        Ok(serde_json::from_str(text)?)
    }

    fn print_object(
        local: &indexmap::IndexMap<String, Box<serde_json::value::RawValue>>,
        remote: &indexmap::IndexMap<String, Box<serde_json::value::RawValue>>,
        merged: &Node,
        indent: &str,
        depth: usize,
        out: &mut String,
    ) -> eyre::Result<()> {
        let Node::Map(entries) = merged else {
            eyre::bail!("json merge expected an object");
        };
        let mut keys = Vec::new();
        for key in local.keys() {
            if entries.contains_key(key) {
                keys.push(key.clone());
            }
        }
        for key in entries.keys() {
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
        if keys.is_empty() {
            out.push_str("{}");
            return Ok(());
        }
        out.push_str("{\n");
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                out.push_str(",\n");
            }
            out.push_str(&indent.repeat(depth + 1));
            out.push_str(&serde_json::to_string(key)?);
            out.push_str(": ");
            match entries.get(key) {
                Some(Node::Map(_)) => {
                    let child_local = local
                        .get(key)
                        .and_then(|raw| raw_object(raw.get()).ok())
                        .unwrap_or_default();
                    let child_remote = remote
                        .get(key)
                        .and_then(|raw| raw_object(raw.get()).ok())
                        .unwrap_or_default();
                    print_object(
                        &child_local,
                        &child_remote,
                        &entries[key],
                        indent,
                        depth + 1,
                        out,
                    )?;
                }
                Some(Node::Atom(atom)) => out.push_str(&owned_raw(local, remote, key, atom)),
                None => eyre::bail!("json merge lost {key}"),
            }
        }
        out.push('\n');
        out.push_str(&indent.repeat(depth));
        out.push('}');
        Ok(())
    }

    fn owned_raw(
        local: &indexmap::IndexMap<String, Box<serde_json::value::RawValue>>,
        remote: &indexmap::IndexMap<String, Box<serde_json::value::RawValue>>,
        key: &str,
        atom: &str,
    ) -> String {
        for side in [local, remote] {
            if let Some(raw) = side.get(key)
                && serde_json::from_str::<Value>(raw.get())
                    .is_ok_and(|value| canonical(&value) == atom)
            {
                return raw.get().to_string();
            }
        }
        atom.to_string()
    }

    pub(super) fn duplicate_keys(text: &str) -> bool {
        scan(&mut text.chars().peekable())
    }

    fn canonical(value: &Value) -> String {
        fn sort(value: Value) -> Value {
            match value {
                Value::Object(map) => {
                    let mut keys: Vec<_> = map.keys().cloned().collect();
                    keys.sort();
                    let mut ordered = serde_json::Map::new();
                    for key in keys {
                        if let Some(child) = map.get(&key) {
                            ordered.insert(key, sort(child.clone()));
                        }
                    }
                    Value::Object(ordered)
                }
                Value::Array(items) => Value::Array(items.into_iter().map(sort).collect()),
                other => other,
            }
        }
        sort(value.clone()).to_string()
    }

    fn scan(chars: &mut std::iter::Peekable<std::str::Chars>) -> bool {
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    skip_string(chars);
                }
                '{' => {
                    if object_has_duplicate(chars) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    fn object_has_duplicate(chars: &mut std::iter::Peekable<std::str::Chars>) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        loop {
            skip_ws(chars);
            if chars.peek() == Some(&'}') {
                chars.next();
                return false;
            }
            let Some(key) = read_string(chars) else {
                return false;
            };
            if !seen.insert(key) {
                return true;
            }
            skip_ws(chars);
            if chars.next() != Some(':') {
                return false;
            }
            if scan(chars) {
                return true;
            }
            skip_ws(chars);
            match chars.next() {
                Some(',') => continue,
                Some('}') => return false,
                _ => return false,
            }
        }
    }

    fn skip_ws(chars: &mut std::iter::Peekable<std::str::Chars>) {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
    }

    fn skip_string(chars: &mut std::iter::Peekable<std::str::Chars>) {
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => break,
                _ => {}
            }
        }
    }

    fn read_string(chars: &mut std::iter::Peekable<std::str::Chars>) -> Option<String> {
        skip_ws(chars);
        if chars.next() != Some('"') {
            return None;
        }
        let mut key = String::new();
        while let Some(c) = chars.next() {
            match c {
                '\\' => key.push(chars.next().unwrap_or_default()),
                '"' => return Some(key),
                other => key.push(other),
            }
        }
        None
    }

    fn indent_of(text: &str) -> String {
        text.lines()
            .find_map(|line| {
                let indent: String = line
                    .chars()
                    .take_while(|c| *c == ' ' || *c == '\t')
                    .collect();
                (!indent.is_empty() && indent.len() < line.len()).then_some(indent)
            })
            .unwrap_or_else(|| "  ".to_string())
    }
}

mod toml_doc {
    use super::Node;
    use toml_edit::{DocumentMut, Item, TableLike};

    pub(super) fn parse(text: &str) -> Result<Node, ()> {
        let value = toml::from_str::<toml::Value>(text).map_err(|_| ())?;
        if !value.is_table() && !text.trim().is_empty() {
            return Err(());
        }
        Ok(from_value(&value))
    }

    fn from_value(value: &toml::Value) -> Node {
        match value {
            toml::Value::Table(table) => Node::Map(
                table
                    .iter()
                    .map(|(key, value)| (key.to_string(), from_value(value)))
                    .collect(),
            ),
            other => Node::Atom(canonical(other)),
        }
    }

    pub(super) fn render(local: &str, merged: &Node) -> eyre::Result<String> {
        let mut document = local.parse::<DocumentMut>()?;
        apply(document.as_table_mut(), merged)?;
        Ok(document.to_string())
    }

    fn apply(target: &mut dyn TableLike, merged: &Node) -> eyre::Result<()> {
        let Node::Map(entries) = merged else {
            eyre::bail!("toml merge expected a table");
        };
        let present: Vec<String> = target.iter().map(|(key, _)| key.to_string()).collect();
        for key in present {
            if !entries.contains_key(&key) {
                target.remove(&key);
            }
        }
        for (key, value) in entries {
            match value {
                Node::Map(children) => {
                    if target
                        .get(key)
                        .and_then(|item| item.as_table_like())
                        .is_none()
                    {
                        target.insert(key, Item::Table(toml_edit::Table::new()));
                    }
                    let Some(child) = target
                        .get_mut(key)
                        .and_then(|item| item.as_table_like_mut())
                    else {
                        eyre::bail!("toml merge could not edit {key}");
                    };
                    apply(child, &Node::Map(children.clone()))?;
                }
                Node::Atom(text) => {
                    if target
                        .get(key)
                        .is_some_and(|item| atom_text(item).as_deref() == Some(text.as_str()))
                    {
                        continue;
                    }
                    let mut parsed = item_from_atom(text)?;
                    if let (Some(old), Some(new)) = (
                        target.get(key).and_then(Item::as_value),
                        parsed.as_value_mut(),
                    ) {
                        *new.decor_mut() = old.decor().clone();
                    }
                    if let Some(existing) = target.get_mut(key) {
                        *existing = parsed;
                    } else {
                        target.insert(key, parsed);
                    }
                }
            }
        }
        Ok(())
    }

    fn atom_text(item: &Item) -> Option<String> {
        let mut wrapped = DocumentMut::new();
        wrapped.insert("value", item.clone());
        toml::from_str::<toml::Table>(&wrapped.to_string())
            .ok()
            .and_then(|mut table| table.remove("value"))
            .as_ref()
            .map(canonical)
    }
    /// Parse an atom as a value under a key. `Item`'s parser does not accept a
    /// bare value, and a value parsed this way keeps the type `toml` read,
    /// including an array of tables written inline.
    fn item_from_atom(text: &str) -> eyre::Result<Item> {
        let wrapped = format!("value = {text}\n");
        let document = wrapped
            .parse::<DocumentMut>()
            .map_err(|err| eyre::eyre!("toml value: {err}"))?;
        document
            .get("value")
            .cloned()
            .ok_or_else(|| eyre::eyre!("toml value was not a value"))
    }
    pub(super) fn duplicate_keys(text: &str) -> bool {
        let Ok(document) = text.parse::<DocumentMut>() else {
            return false;
        };
        table_duplicates(document.as_table())
    }

    fn table_duplicates(table: &dyn TableLike) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        for (key, item) in table.iter() {
            if !seen.insert(key.to_string()) {
                return true;
            }
            if let Some(child) = item.as_table_like() {
                if table_duplicates(child) {
                    return true;
                }
            }
        }
        false
    }

    fn canonical(value: &toml::Value) -> String {
        match value {
            toml::Value::Array(items) => {
                let inner = items.iter().map(canonical).collect::<Vec<_>>().join(", ");
                format!("[{inner}]")
            }
            toml::Value::Table(table) => {
                let mut keys: Vec<_> = table.keys().cloned().collect();
                keys.sort();
                let inner = keys
                    .iter()
                    .map(|key| {
                        format!(
                            "{} = {}",
                            toml_edit::Key::new(key).to_string(),
                            canonical(&table[key])
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{{{inner}}}")
            }
            other => other.to_string(),
        }
    }
}

mod yaml_doc {
    use super::Node;
    use std::str::FromStr;

    pub(super) fn parse(text: &str) -> Result<Node, ()> {
        if unsupported_syntax(text) {
            return Err(());
        }
        if text.trim().is_empty() {
            return Ok(Node::Map(indexmap::IndexMap::new()));
        }
        let value = mise_util::yaml::from_str::<mise_util::yaml::Value>(text).map_err(|_| ())?;
        from_value(&value)
    }

    fn unsupported_syntax(text: &str) -> bool {
        use yaml_edit::SyntaxKind;
        let tokens = yaml_edit::lex(text);
        tokens.iter().any(|(kind, _)| {
            matches!(
                kind,
                SyntaxKind::ANCHOR
                    | SyntaxKind::REFERENCE
                    | SyntaxKind::MERGE_KEY
                    | SyntaxKind::TAG
            )
        }) || tokens
            .iter()
            .filter(|(kind, _)| *kind == SyntaxKind::DOCUMENT)
            .count()
            > 1
    }

    pub(super) fn duplicate_keys(text: &str) -> bool {
        let Ok(file) = yaml_edit::YamlFile::from_str(text) else {
            return false;
        };
        if file.documents().count() > 1 {
            return false;
        }
        let Some(mapping) = file.document().and_then(|document| document.as_mapping()) else {
            return false;
        };
        mapping_duplicates(&mapping)
    }

    fn mapping_duplicates(mapping: &yaml_edit::Mapping) -> bool {
        let mut seen = std::collections::BTreeSet::new();
        for key in mapping.keys() {
            let Some(name) = scalar_text(&key) else {
                continue;
            };
            if !seen.insert(name) {
                return true;
            }
            if let Some(child) = mapping
                .get(&key)
                .and_then(|node| node.as_mapping().cloned())
            {
                if mapping_duplicates(&child) {
                    return true;
                }
            }
        }
        false
    }

    fn scalar_text(node: &yaml_edit::YamlNode) -> Option<String> {
        node.as_scalar().as_ref().map(|scalar| scalar.as_string())
    }

    fn from_value(value: &mise_util::yaml::Value) -> Result<Node, ()> {
        match value {
            mise_util::yaml::Value::Mapping(map) => {
                let mut entries = indexmap::IndexMap::new();
                for (key, value) in map {
                    let Some(key) = key.as_str() else {
                        return Err(());
                    };
                    entries.insert(key.to_string(), from_value(value)?);
                }
                Ok(Node::Map(entries))
            }
            other => {
                if contains_non_string_key(other) {
                    return Err(());
                }
                Ok(Node::Atom(canonical(other)))
            }
        }
    }

    fn contains_non_string_key(value: &mise_util::yaml::Value) -> bool {
        match value {
            mise_util::yaml::Value::Mapping(map) => map
                .iter()
                .any(|(key, value)| key.as_str().is_none() || contains_non_string_key(value)),
            mise_util::yaml::Value::Sequence(items) => items.iter().any(contains_non_string_key),
            _ => false,
        }
    }

    fn canonical(value: &mise_util::yaml::Value) -> String {
        match value {
            mise_util::yaml::Value::String(text) => serde_json::to_string(text).unwrap_or_default(),
            mise_util::yaml::Value::Bool(flag) => flag.to_string(),
            mise_util::yaml::Value::Number(number) => number.to_string(),
            mise_util::yaml::Value::Sequence(items) => {
                let inner = items.iter().map(canonical).collect::<Vec<_>>().join(",");
                format!("[{inner}]")
            }
            mise_util::yaml::Value::Mapping(map) => {
                let mut keys: Vec<_> = map.keys().filter_map(|key| key.as_str()).collect();
                keys.sort_unstable();
                let inner = keys
                    .iter()
                    .filter_map(|key| {
                        map.get(&mise_util::yaml::Value::from(*key)).map(|value| {
                            format!(
                                "{}:{}",
                                serde_json::to_string(key).unwrap_or_default(),
                                canonical(value)
                            )
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{inner}}}")
            }
            mise_util::yaml::Value::Null => "null".to_string(),
        }
    }

    pub(super) fn render(local: &str, remote: &str, merged: &Node) -> eyre::Result<String> {
        if !matches!(merged, Node::Map(_)) {
            eyre::bail!("a non-map YAML root is kept only as one side's own text");
        }
        let file =
            yaml_edit::YamlFile::from_str(local).map_err(|err| eyre::eyre!("yaml: {err}"))?;
        if file.documents().count() > 1 {
            eyre::bail!("yaml merge expected one document");
        }
        let Some(mapping) = file.document().and_then(|document| document.as_mapping()) else {
            eyre::bail!("yaml merge expected a mapping");
        };
        let remote_file = yaml_edit::YamlFile::from_str(remote).ok();
        let remote_mapping = remote_file.as_ref().and_then(|file| {
            if file.documents().count() > 1 {
                return None;
            }
            file.document().and_then(|document| document.as_mapping())
        });
        apply(&mapping, remote_mapping.as_ref(), merged)?;
        Ok(file.to_string())
    }

    fn apply(
        local: &yaml_edit::Mapping,
        remote: Option<&yaml_edit::Mapping>,
        merged: &Node,
    ) -> eyre::Result<()> {
        let Node::Map(entries) = merged else {
            eyre::bail!("yaml merge expected a mapping");
        };
        let present: Vec<String> = local.keys().filter_map(|key| scalar_text(&key)).collect();
        for key in &present {
            if !entries.contains_key(key) {
                local.remove(key.as_str());
            }
        }
        for (key, value) in entries {
            match value {
                Node::Map(_) => {
                    let local_child = local
                        .get(key.as_str())
                        .and_then(|node| node.as_mapping().cloned());
                    let remote_child = remote
                        .and_then(|mapping| mapping.get(key.as_str()))
                        .and_then(|node| node.as_mapping().cloned());
                    if let Some(child) = local_child {
                        apply(&child, remote_child.as_ref(), value)?;
                    } else if let Some(child) = remote_child {
                        local.set(key.as_str(), &child);
                    } else {
                        eyre::bail!("yaml merge could not edit {key}");
                    }
                }
                Node::Atom(atom) => {
                    if local
                        .get(key.as_str())
                        .is_some_and(|node| node_matches(&node, atom))
                    {
                        continue;
                    }
                    let Some(source) = remote
                        .and_then(|mapping| mapping.get(key.as_str()))
                        .filter(|node| node_matches(node, atom))
                    else {
                        eyre::bail!("yaml merge has no source text for {key}");
                    };
                    replace_value(local, key, &source);
                }
            }
        }
        Ok(())
    }

    fn replace_value(target: &yaml_edit::Mapping, key: &str, value: &yaml_edit::YamlNode) {
        let existing_text = target
            .get(key)
            .map(|node| node.to_string())
            .unwrap_or_default();
        if existing_text.trim_start().starts_with(['|', '>'])
            && let Some(index) = target
                .keys()
                .position(|existing| scalar_text(&existing).as_deref() == Some(key))
        {
            target.remove(key);
            target.insert_at_index(index, key, value);
            return;
        }
        target.set(key, value);
    }

    fn node_matches(node: &yaml_edit::YamlNode, atom: &str) -> bool {
        mise_util::yaml::from_str::<mise_util::yaml::Value>(&node.to_string())
            .is_ok_and(|value| canonical(&value) == atom)
    }
}
