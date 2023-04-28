use halo2_proofs::{circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation, arithmetic::Field};

#[derive(Debug, Clone)]
pub struct AddCarryV2Config {
    pub advice: [Column<Advice>; 4],
    pub instance: Column<Instance>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct AddCarryV2Chip {
    config: AddCarryV2Config,
}

impl AddCarryV2Chip {
    pub fn construct(config: AddCarryV2Config) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 4],
        selector: Selector,
        instance: Column<Instance>,
    ) -> AddCarryV2Config {
        let col_a = advice[0];
        let col_b_inv = advice[1];
        let col_b = advice[2];
        let col_c = advice[3];
        let add_carry_selector = selector;

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(col_a);
        meta.enable_equality(col_b_inv);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        // This custom gate has two constraints:
        // 1. for each row, the previous accumulator amount + new value from a_cell
        // 2. left most accumulator bit is zero for checking overflow
        // Note that, if the value 'a' is more than 16bits, this chip could not get the correct result
        meta.create_gate("accumulate constraint", |meta| {
            let s = meta.query_selector(add_carry_selector);
            let prev_b = meta.query_advice(col_b, Rotation::prev());
            let prev_c = meta.query_advice(col_c, Rotation::prev());
            let a = meta.query_advice(col_a, Rotation::cur());
            let b_inv = meta.query_advice(col_b_inv, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());

            // Previous accumulator amount + new value from a_cell
            // using binary expression (x_n-4 * 2^16) + (x_n-3 * 2^8) + ... + (x_n * 2)
            vec![
                s.clone() * ((a + (prev_b * Expression::Constant(Fp::from(1 << 16))) + prev_c)
                    - ((b.clone() * Expression::Constant(Fp::from(1 << 16))) + c)),

                // check 'b' is zero
                s * b.clone() * (Expression::Constant(Fp::one()) - b.clone() * b_inv)
            ]
        });

        AddCarryV2Config {
            advice: [col_a, col_b_inv, col_b, col_c],
            instance,
            selector: add_carry_selector,
        }
    }

    // Initial accumulator values from instance for expreiment
    pub fn assign_first_row(
        &self,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        layouter.assign_region(
            || "first row",
            |mut region| {
                let b_cell = region.assign_advice_from_instance(
                    || "first acc[1]",
                    self.config.instance,
                    0,
                    self.config.advice[2],
                    0,
                )?;

                let c_cell = region.assign_advice_from_instance(
                    || "first acc[2]",
                    self.config.instance,
                    1,
                    self.config.advice[3],
                    0,
                )?;

                Ok((b_cell, c_cell))
            },
        )
    }

    pub fn assign_advice_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        prev_b: AssignedCell<Fp, Fp>,
        prev_c: AssignedCell<Fp, Fp>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        layouter.assign_region(
            || "adivce row for accumulating",
            |mut region| {
                // enable hash selector
                self.config.selector.enable(&mut region, 1)?;

                let _ = prev_b.copy_advice(|| "prev_b", &mut region, self.config.advice[2], 0);
                let _ = prev_c.copy_advice(|| "prev_c", &mut region, self.config.advice[3], 0);

                // Assign new amount to the cell inside the region
                region.assign_advice(|| "a", self.config.advice[0], 1, || a)?;

                // combine accumulated value and new
                let mut sum = Fp::zero();
                a.as_ref().map(|f| sum = sum.add(f));
                prev_b
                    .value()
                    .map(|b| sum = sum.add(&b.mul(&Fp::from(1 << 16))));
                prev_c.value().map(|c| sum = sum.add(c));

                // split by 16bits for two accumulator columns
                // Alternatives
                // option1. using additional advice column for calculation
                // option2. using lookup table for precalulated
                let max_bits = Fp::from(1 << 16);
                let split_by_16bits = || {
                    let mut remains = sum.clone();
                    let mut accumulator = Fp::zero();
                    while remains >= max_bits {
                        remains = remains.sub(&max_bits);
                        accumulator = accumulator.add(&Fp::one());
                    }
                    (accumulator, remains)
                };

                let (hi, lo) = split_by_16bits();

                // assigning two columns of accumulating value
                let b_cell = region.assign_advice(
                    || "sum_hi",
                    self.config.advice[2],
                    1,
                    || Value::known(hi),
                )?;
                let c_cell = region.assign_advice(
                    || "sum_lo",
                    self.config.advice[3],
                    1,
                    || Value::known(lo),
                )?;

                let b_inv = Value::known(hi).map(|value| value.invert().unwrap_or(Fp::zero()));

                region.assign_advice(|| "b inv", self.config.advice[1], 1, || b_inv)?;

                Ok((b_cell, c_cell))
            },
        )
    }

    // Enforce permutation check between b & cell and instance column
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
