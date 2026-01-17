import pool from "../db";
import type { OwnerContext } from "../constants/owner";
import type { IocType } from "../constants/provider.interface";

interface LogIocHistoryParams {
  owner: OwnerContext;
  iocType: IocType;
  iocValue: string;
  verdict: string;
  score: number;
}


export async function logIocHistory({
  owner,
  iocType,
  iocValue,
  verdict,
  score,
}: LogIocHistoryParams): Promise<void> {
  await pool.query(
    `
    INSERT INTO ioc_history (
      owner_type,
      owner_id,
      ioc_type,
      ioc_value,
      verdict,
      score
    )
    VALUES ($1, $2, $3, $4, $5, $6)
    `,
    [
      owner.type,
      owner.id,
      iocType,
      iocValue,
      verdict,
      score,
    ]
  );
}
