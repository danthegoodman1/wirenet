-- name: GetNetwork :one
SELECT * FROM networks WHERE id = $1;

-- name: GetNetworkByName :one
SELECT * FROM networks WHERE name = $1;

-- name: ListNetworks :many
SELECT * FROM networks ORDER BY id;

-- PutNetwork, like every put of a named record, writes nothing when another
-- record holds the name. Checking first, rather than relying on the unique
-- index, keeps the transaction usable, and makes a concurrent insert of the
-- name a serialization failure, which Update retries.
-- name: PutNetwork :execrows
INSERT INTO networks (id, name, prefix6, prefix4, mtu, relays, next6, next4, revision, created, changed, quota)
SELECT @id, @name, @prefix6, @prefix4, @mtu, @relays, @next6, @next4, @revision, @created, @changed, @quota
WHERE NOT EXISTS (SELECT 1 FROM networks AS o WHERE o.name = @name AND o.id <> @id)
ON CONFLICT (id) DO UPDATE SET
	name = excluded.name, prefix6 = excluded.prefix6, prefix4 = excluded.prefix4,
	mtu = excluded.mtu, relays = excluded.relays, next6 = excluded.next6,
	next4 = excluded.next4, revision = excluded.revision, created = excluded.created,
	changed = excluded.changed, quota = excluded.quota;

-- name: DeleteNetwork :exec
DELETE FROM networks WHERE id = $1;

-- name: GetService :one
SELECT * FROM services WHERE id = $1;

-- name: GetServiceByName :one
SELECT * FROM services WHERE network = $1 AND name = $2;

-- name: ListServices :many
SELECT * FROM services WHERE network = $1 ORDER BY id;

-- name: PutService :execrows
INSERT INTO services (id, network, name, ipv4, addr6, addr4, mode, created)
SELECT @id, @network, @name, @ipv4, @addr6, @addr4, @mode, @created
WHERE NOT EXISTS (
	SELECT 1 FROM services AS o WHERE o.network = @network AND o.name = @name AND o.id <> @id
)
ON CONFLICT (id) DO UPDATE SET
	network = excluded.network, name = excluded.name, ipv4 = excluded.ipv4,
	addr6 = excluded.addr6, addr4 = excluded.addr4, mode = excluded.mode,
	created = excluded.created;

-- name: DeleteService :exec
DELETE FROM services WHERE id = $1;

-- name: GetRule :one
SELECT * FROM rules WHERE id = $1;

-- name: ListRules :many
SELECT * FROM rules WHERE network = $1 ORDER BY id;

-- name: PutRule :exec
INSERT INTO rules (id, network, from_service, to_service, proto, port_lo, port_hi, created, deny)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (id) DO UPDATE SET
	network = excluded.network, from_service = excluded.from_service,
	to_service = excluded.to_service, proto = excluded.proto,
	port_lo = excluded.port_lo, port_hi = excluded.port_hi, created = excluded.created,
	deny = excluded.deny;

-- name: DeleteRule :exec
DELETE FROM rules WHERE id = $1;
