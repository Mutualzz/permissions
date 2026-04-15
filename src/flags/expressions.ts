export const expressionFlags = {
    Animated: 1n << 0n,
};

export type ExpressionFlag = keyof typeof expressionFlags;
export type ExpressionFlags = typeof expressionFlags;
