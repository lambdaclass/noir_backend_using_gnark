package components

import "gnark_backend_ffi/backend"

// (trueValue - falseValue) * condition + falseValue
// If condition = 0 => (trueValue - falseValue) * 0 + falseValue = falseValue
// If condition = 0 => (trueValue - falseValue) * 1 + falseValue = trueValue
func Select(condition, trueValue, falseValue int, ctx *backend.Context, unconstrainedCondition bool) int {
	if unconstrainedCondition {
		assertIsBoolean(condition, ctx.ConstraintSystem)
	}
	trueValueMinusFalseValue := sub(trueValue, falseValue, ctx)
	trueValueMinusFalseValueTimesCondition := mul(trueValueMinusFalseValue, condition, ctx)
	return add(trueValueMinusFalseValueTimesCondition, falseValue, ctx)
}
