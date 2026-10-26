-- SQLite selects the first duplicate JSON key; serde_json selects the last.
-- Decode every object key before indexing, including escaped and nested keys.
-- Only migration and per-row payload mutations traverse the JSON tree.
ALTER TABLE relay_inbox ADD COLUMN initial_secret_ambiguous INTEGER NOT NULL DEFAULT 1;
UPDATE relay_inbox SET initial_secret_ambiguous = CASE
    WHEN json_valid(CAST(prepared_operation AS TEXT)) THEN EXISTS (
        SELECT 1 FROM json_tree(CAST(prepared_operation AS TEXT))
        WHERE typeof(key)='text' GROUP BY parent,key HAVING COUNT(*)>1
    ) ELSE 1 END;
CREATE TRIGGER relay_inbox_initial_secret_insert AFTER INSERT ON relay_inbox
BEGIN
    UPDATE relay_inbox SET initial_secret_ambiguous = CASE
        WHEN json_valid(CAST(NEW.prepared_operation AS TEXT)) THEN EXISTS (
            SELECT 1 FROM json_tree(CAST(NEW.prepared_operation AS TEXT))
            WHERE typeof(key)='text' GROUP BY parent,key HAVING COUNT(*)>1
        ) ELSE 1 END
    WHERE rowid=NEW.rowid;
END;
CREATE TRIGGER relay_inbox_initial_secret_update AFTER UPDATE OF prepared_operation ON relay_inbox
BEGIN
    UPDATE relay_inbox SET initial_secret_ambiguous = CASE
        WHEN json_valid(CAST(NEW.prepared_operation AS TEXT)) THEN EXISTS (
            SELECT 1 FROM json_tree(CAST(NEW.prepared_operation AS TEXT))
            WHERE typeof(key)='text' GROUP BY parent,key HAVING COUNT(*)>1
        ) ELSE 1 END
    WHERE rowid=NEW.rowid;
END;
-- Virtual columns keep historical payload bytes intact. Index construction does
-- the backfill at migration time; subsequent mutations classify only their row.
ALTER TABLE relay_inbox ADD COLUMN initial_secret_document TEXT GENERATED ALWAYS AS (
    CASE WHEN json_valid(CAST(prepared_operation AS TEXT)) THEN
        CASE WHEN json_type(CAST(prepared_operation AS TEXT),'$.schema_version') IS NULL
            THEN CAST(prepared_operation AS TEXT)
        WHEN json_extract(CAST(prepared_operation AS TEXT),'$.schema_version') IS '1'
            AND json_type(CAST(prepared_operation AS TEXT),'$.operation') = 'object'
            THEN json_extract(CAST(prepared_operation AS TEXT),'$.operation')
        END
    END
) VIRTUAL;
-- Empty text is conservative evidence for every pair of this signer. NULL is
-- ordinary message history. All other values are SetChatSecret namespaces.
ALTER TABLE relay_inbox ADD COLUMN initial_secret_chat_id TEXT GENERATED ALWAYS AS (
    CASE WHEN initial_secret_ambiguous != 0 OR initial_secret_document IS NULL THEN ''
        WHEN json_type(initial_secret_document,'$.operation.SetChatSecret') IS NOT NULL THEN
            CASE WHEN json_type(initial_secret_document,'$.operation.SetChatSecret.chat_id') = 'text'
                THEN json_extract(initial_secret_document,'$.operation.SetChatSecret.chat_id') ELSE '' END
        WHEN json_type(initial_secret_document,'$.operation.MessageSend') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageEdit') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReactionAdd') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReactionRemove') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageDelete') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageDeleteLive') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageState') = 'object'
          OR json_type(initial_secret_document,'$.operation.MessageReceived') = 'object'
          OR json_type(initial_secret_document,'$.operation.AddConversation') = 'object'
            THEN NULL
        ELSE ''
    END
) VIRTUAL;
CREATE INDEX relay_inbox_initial_secret ON relay_inbox(signer_principal,initial_secret_chat_id)
WHERE prepared_operation IS NOT NULL AND state!='rejected';
