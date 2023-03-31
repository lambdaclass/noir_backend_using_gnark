package components

import (
	"gnark_backend_ffi/backend"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

// Generates constraints for adding two elliptic curve points.
//
// Generates 7 constraints if the point needs to be checked and 2 constraints if not.
// A point addition result could not be checked as an optimization in the case that
// the resulting point is a partial result of a multiple addition for example.
// The user should take this into account.
//
// augendPointX is the index to the x-coordinate of the augend point in question.
// augendPointY is the index to the y-coordinate of the augend point in question.
// addendPointX is the index to the x-coordinate of the addend point in question.
// addendPointY is the index to the y-coordinate of the addend point in question.
// ctx is the context.
// checkPoint is a flag that will generate additional constraints for checking
// that the resulting point is on the curve.
//
// Returns the indices to the resulting point x and y coordinates.
func AddPoints(augendPointX, augendPointY, addendPointX, addendPointY int, ctx *backend.Context, checkPoint bool) (newPointX, newPointY int) {
	newPointX = add(augendPointX, addendPointX, ctx)
	newPointY = add(augendPointY, addendPointY, ctx)
	if checkPoint {
		AssertPointIsOnCurve(newPointX, newPointY, ctx)
	}
	return
}

// Generates constraints for doubling a point. Doubling a point means adding some
// point to itself.
//
// Generates 7 constraints if the point needs to be checked and 2 constraints if not.
// A point addition result could not be checked as an optimization in the case that
// the resulting point is a partial result of a multiple addition for example.
// The user should take this into account.
//
// x is the index to the x-coordinate of the point in question.
// y is the index to the y-coordinate of the point in question.
// ctx is the context.
// checkPoint is a flag that will generate additional constraints for checking
// that the resulting point is on the curve.
//
// Returns the indices to the resulting point x and y coordinates.
func DoublePoint(x, y int, ctx *backend.Context, checkPoint bool) (doubledX, doubledY int) {
	return AddPoints(x, y, x, y, ctx, checkPoint)
}

// Generates constraints for computing the fixed base scalar multiplication. This
// means multiplying the curve generator with a given scalar.
//
// Generates 5n + 1 constraints where n is the integer value of the scalar.
//
// scalar is the index to the concrete value of the scalar that will multiply
// the curve generator.
// ctx is the context.
func ScalarBaseMul(scalar int, ctx *backend.Context) (resultX, resultY int) {
	switch ctx.ConstraintSystem.(type) {
	case *cs_bn254.SparseR1CS:
		_, _, generator, _ := bn254.Generators()
		x := ctx.AddSecretVariable("genX", fr_bn254.Element(generator.X))
		y := ctx.AddSecretVariable("genY", fr_bn254.Element(generator.Y))
		accumulatorX, accumulatorY := AddPoints(x, y, x, y, ctx, false)
		for i := 0; i < int(ctx.Variables[scalar].Uint64()); i++ {
			accumulatorX, accumulatorY = DoublePoint(x, y, ctx, false)
		}
		AssertPointIsOnCurve(accumulatorX, accumulatorY, ctx)
		resultX = accumulatorX
		resultY = accumulatorY
		return
	}
	return
}
