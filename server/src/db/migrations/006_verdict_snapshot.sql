-- adding verdict, score to ioc_history

ALTER TABLE ioc_history
ADD COLUMN verdict TEXT;

ALTER TABLE ioc_history
ADD COLUMN score INT;
