import pool from "../db";
import type { OwnerContext } from "../constants/owner";
import type { IocType } from "../constants/provider.interface";

interface LogIocHistoryParams {
  owner: OwnerContext;
  iocType: IocType;
  iocValue: string;
}

export async function logIocHistory({
  owner,
  iocType,
  iocValue,
}: LogIocHistoryParams): Promise<void> {
  await pool.query(
    `
    INSERT INTO ioc_history (owner_type, owner_id, ioc_type, ioc_value)
    VALUES ($1, $2, $3, $4)
    `,
    [owner.type, owner.id, iocType, iocValue]
  );
}
  