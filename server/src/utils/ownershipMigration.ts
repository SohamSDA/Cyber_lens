import pool from "../db";
import { OwnerType } from "../constants/owner";

interface OwnershipMigrationTask {
  table: string;
  ownerTypeColumn: string;
  ownerIdColumn: string;
}

// Add table mappings here as new features store owner references.
const MIGRATION_TASKS: OwnershipMigrationTask[] = [
  {
    table: "ioc_history",
    ownerTypeColumn: "owner_type",
    ownerIdColumn: "owner_id",
  },
];

export async function migrateAnonymousOwnerToUser(
  anonymousId: string,
  userId: string
): Promise<void> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    for (const task of MIGRATION_TASKS) {
      await client.query(
        `UPDATE ${task.table}
         SET ${task.ownerTypeColumn} = $1, ${task.ownerIdColumn} = $2
         WHERE ${task.ownerTypeColumn} = $3 AND ${task.ownerIdColumn} = $4`,
        ["user" satisfies OwnerType, userId, "anonymous" satisfies OwnerType, anonymousId]
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export function registerOwnershipMigrationTask(task: OwnershipMigrationTask): void {
  MIGRATION_TASKS.push(task);
}
