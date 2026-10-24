-- A host's scope: global admits every network, otherwise networks is a JSON
-- array of the network identifiers it admits. Hosts registered before
-- scopes are global.
ALTER TABLE hosts ADD COLUMN global boolean NOT NULL DEFAULT true;
ALTER TABLE hosts ALTER COLUMN global DROP DEFAULT;
ALTER TABLE hosts ADD COLUMN networks jsonb NOT NULL DEFAULT '[]';
ALTER TABLE hosts ALTER COLUMN networks DROP DEFAULT;

-- An admin token manages the networks its scope admits.
CREATE TABLE admins (
	id         text COLLATE "C" PRIMARY KEY,
	name       text COLLATE "C" NOT NULL UNIQUE,
	token_hash bytea NOT NULL,
	global     boolean NOT NULL,
	networks   jsonb NOT NULL,
	created    timestamptz NOT NULL
);
CREATE INDEX admins_token ON admins (token_hash, id);

-- quota is a JSON api.Quota; an empty object bounds nothing.
ALTER TABLE networks ADD COLUMN quota jsonb NOT NULL DEFAULT '{}';
ALTER TABLE networks ALTER COLUMN quota DROP DEFAULT;
