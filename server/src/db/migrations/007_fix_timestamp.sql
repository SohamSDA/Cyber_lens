ALTER TABLE ioc_history
  ALTER COLUMN created_at
  SET DATA TYPE TIMESTAMP WITH TIME ZONE
  USING created_at AT TIME ZONE 'UTC';

ALTER TABLE ioc_history
  ALTER COLUMN created_at
  SET DEFAULT NOW();

UPDATE ioc_history
SET verdict = 'unknown'
WHERE verdict IS NULL;

UPDATE ioc_history
SET score = 0
WHERE score IS NULL;

ALTER TABLE ioc_history
  ALTER COLUMN verdict SET NOT NULL,
  ALTER COLUMN score SET NOT NULL;
