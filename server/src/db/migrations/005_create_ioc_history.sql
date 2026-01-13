CREATE TABLE ioc_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  owner_type TEXT NOT NULL,
  owner_id UUID NOT NULL,

  ioc_type TEXT NOT NULL,
  ioc_value TEXT NOT NULL,

  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
