# Sovereign SIMD Balance Kernel in Mojo
# Computes tension between Drive (curiosity, ambition, velocity, problem-solving)
# and Humanity (discipline, resonance, ethics, restraint).
#
# Supports:
# 1. Scalar invocation: balance <drive_scalar> <humanity_scalar>
# 2. SIMD vector invocation: balance <d_curiosity> <d_ambition> <d_velocity> <d_solve> <h_discipline> <h_resonance> <h_ethics> <h_restraint>

from std.sys import argv

def main() raises:
    var args = argv()
    var count = len(args)
    if count < 3:
        print('{"error":"usage: balance <drive> <humanity> or balance <d0> <d1> <d2> <d3> <h0> <h1> <h2> <h3>"}')
        return

    var drive_sum: Float64
    var humanity_sum: Float64
    var mode: String

    if count >= 9:
        var d0 = Float32(atol(String(args[1])))
        var d1 = Float32(atol(String(args[2])))
        var d2 = Float32(atol(String(args[3])))
        var d3 = Float32(atol(String(args[4])))

        var h0 = Float32(atol(String(args[5])))
        var h1 = Float32(atol(String(args[6])))
        var h2 = Float32(atol(String(args[7])))
        var h3 = Float32(atol(String(args[8])))

        var drive_simd = SIMD[DType.float32, 4](d0, d1, d2, d3)
        var human_simd = SIMD[DType.float32, 4](h0, h1, h2, h3)

        drive_sum = Float64(drive_simd.reduce_add())
        humanity_sum = Float64(human_simd.reduce_add())
        mode = "simd-vector-4"
    else:
        drive_sum = Float64(atol(String(args[1])))
        humanity_sum = Float64(atol(String(args[2])))
        mode = "scalar"

    if drive_sum == 0.0 and humanity_sum == 0.0:
        print('{"kernel":"mojo","mode":"' + mode + '","drive":0.0,"humanity":0.0,"ratio":0.0,"score":0.0,"verdict":"dormant","guidance":"Baseline absent. Both drive and humanity are zero."}')
        return

    if humanity_sum == 0.0:
        print('{"kernel":"mojo","mode":"' + mode + '","drive":' + String(drive_sum) + ',"humanity":0.0,"ratio":999.0,"score":0.1,"verdict":"drive_dominant","guidance":"Humanity absent. Restraint and ethics required."}')
        return

    if drive_sum == 0.0:
        print('{"kernel":"mojo","mode":"' + mode + '","drive":0.0,"humanity":' + String(humanity_sum) + ',"ratio":0.0,"score":0.1,"verdict":"humanity_dominant","guidance":"Drive absent. Ambition and curiosity required."}')
        return

    var ratio = drive_sum / humanity_sum
    var verdict: String
    var guidance: String
    var score: Float64

    if ratio > 2.0:
        verdict = "drive_dominant"
        guidance = "Drive exceeds humanity threshold. Slow down and verify discipline."
        score = 2.0 / ratio
    elif ratio < 0.5:
        verdict = "humanity_dominant"
        guidance = "Humanity suppresses drive. Increase problem-solving velocity."
        score = ratio * 2.0
    else:
        verdict = "balanced"
        guidance = "Tension harmonized. Proceed with atomic ratification."
        if ratio <= 1.0:
            score = ratio
        else:
            score = 1.0 / ratio

    print('{"kernel":"mojo","mode":"' + mode + '","drive":' + String(drive_sum) + ',"humanity":' + String(humanity_sum) + ',"ratio":' + String(ratio) + ',"score":' + String(score) + ',"verdict":"' + verdict + '","guidance":"' + guidance + '"}')
