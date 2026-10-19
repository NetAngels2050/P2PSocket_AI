// 邀请码校验（与服务端 GroupService.InviteCharset 同口径：数字 2-9 + 小写字母去
// o/i/l，31 字符，设计 03 §3 / OQ-17）。大写抄写放行（i 标志）——提交前须经
// normalizeInviteCode 归一：服务端 SQLite BINARY 比较大小写敏感，直接发大写必 3001。
export const INVITE_CODE_PATTERN = /^[2-9a-hjkmnp-z]{6}$/i;
export const INVITE_CODE_MESSAGE = "邀请码为 6 位去混淆字符（数字 2-9 + 小写字母，不含 0/1/o/i/l）";

/** 提交归一：去首尾空白 + 转小写（混淆字符 0/1/o/i/l 不在其中，无自动映射——如实拒绝）。 */
export function normalizeInviteCode(value: string): string {
  return value.trim().toLowerCase();
}
