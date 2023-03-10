use dep::std;

fn main(x: pub Field, y: Field) {
    let p = x == y;
    constrain p == true;
}
