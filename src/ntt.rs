use ::param::{ Q, N, W};


#[inline] fn muln(x: i32, y: i32, n: i32) -> i32 {
    ((x as i64 * y as i64) % n as i64) as i32
}

#[inline] fn sqrn(x: i32, n: i32) -> i32 {
    muln(x, x, n)
}

pub fn pwr(mut x: i32, mut e: i32, n: i32) -> i32 {
    let mut y = if e & 1 != 0 { x } else { 1 };
    e >>= 1;

    while e > 0 {
        x = sqrn(x, n);
        if e & 1 != 0 {
            y = muln(x, y, n);
        }
        e >>= 1;
    }

    y
}

pub fn fft(v: &mut [i32]) {
    let mut j = N >> 1;
    for i in 1..(N - 1) {
        if i < j { v.swap(i, j) };
        let mut k = N;
        loop {
            k >>= 1;
            j ^= k;
            if (j & k) != 0 { break };
        }
    }

    let mut i = 1;
    while i < N {
        let l = N / i;

        for k in (0..N).step_by(i + i) {
            let x = v[k + i];
            v[k + i] = v[k] - x;
            v[k] +=  x;
        }

        for j in 1..i {
            let y = W[j * l];
            for k in (j..N).step_by(i + i) {
                let x = muln(v[k + i], y, Q);
                v[k + i] = v[k] - x;
                v[k] += x;
            }
        }

        i <<= 1;
    }
}

pub fn xmu(v: &mut [i32], t: &[i32], u: &[i32]) {
    for i in 0..N {
        v[i] = muln(t[i], u[i], Q);
    }
}

pub fn cmu(v: &mut [i32], t: &[i32], c: i32) {
    for i in 0..N {
        let x = muln(t[i], c, Q);
        v[i] = if x < 0 { x + Q } else { x };
    }
}

pub fn flp(v: &mut [i32]) {
    let (mut i, mut j) = (1, N - 1);
    while i < j {
        v.swap(i, j);
        i += 1;
        j -= 1;
    }
    v[0] = -v[0];

    for i in 0..N {
        let mut x = v[i];
        if x < 0 { x += Q };
        if x >= Q { x -= Q };
        v[i] = x;
    }
}
