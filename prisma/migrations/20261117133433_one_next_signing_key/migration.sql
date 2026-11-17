-- At most one NEXT signing key (a separate migration: a new enum value cannot be used in the
-- transaction that adds it).
CREATE UNIQUE INDEX "signing_keys_one_next" ON "signing_keys" ("status") WHERE "status" = 'NEXT';
