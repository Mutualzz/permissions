export type Snowflake = string;

export interface RoleLike {
    id: Snowflake;
    permissions: bigint | string;
}

export interface MemberRoleLike {
    roleId: Snowflake;
}

export interface OverwriteLike {
    roleId?: Snowflake | null;
    userId?: Snowflake | null;
    allow: bigint | string;
    deny: bigint | string;
}
