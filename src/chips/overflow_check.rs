use halo2_proofs::{
    arithmetic::Field, circuit::*, halo2curves::pasta::Fp, plonk::*, poly::Rotation,
};
use super::is_zero::{IsZeroChip, IsZeroConfig};
use super::utils::add_carry;

#[derive(Debug, Clone)]
pub struct OverFlowCheckConfig {
    pub advice: [Column<Advice>; 5],
    pub instance: Column<Instance>,
    pub is_zero: IsZeroConfig,
    pub selector: [Selector; 2],
}

#[derive(Debug, Clone)]
pub struct OverFlowChip {
    config: OverFlowCheckConfig,
}

impl OverFlowChip {
    pub fn construct(config: OverFlowCheckConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 5],
        selector: [Selector; 2],
        instance: Column<Instance>,
    ) -> OverFlowCheckConfig {
        let col_a = advice[0];
        let col_b_inv = advice[1];
        let col_b = advice[2];
        let col_c = advice[3];
        let col_d = advice[4];
        let add_carry_selector = selector[0];
        let overflow_check_selector = selector[1];
        let is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(overflow_check_selector),
            |meta| meta.query_advice(col_b, Rotation::cur()),
            // |meta| meta.query_advice(col_b_inv, Rotation::cur())
            col_b_inv
        );

        // Enable equality on the advice and instance column to enable permutation check
        meta.enable_equality(col_a);
        meta.enable_equality(col_b_inv);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(col_d);
        meta.enable_equality(instance);

        // enforce dummy hash function by creating a custom gate
        meta.create_gate("accumulate constraint", |meta| {
            let s_add = meta.query_selector(add_carry_selector);
            let s_over = meta.query_selector(overflow_check_selector);
            let prev_b = meta.query_advice(col_b, Rotation::prev());
            let prev_c = meta.query_advice(col_c, Rotation::prev());
            let prev_d = meta.query_advice(col_d, Rotation::prev());
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let d = meta.query_advice(col_d, Rotation::cur());

            // Previous accumulator amount + new value from a_cell
            // using binary expression (x_n-4 * 2^16) + (x_n-3 * 2^8) + ... + (x_n * 2)
            vec![
                s_add
                    * ((a
                        + (prev_b * Expression::Constant(Fp::from(1 << 32)))
                        + (prev_c * Expression::Constant(Fp::from(1 << 16)))
                        + prev_d)
                        - ((b.clone() * Expression::Constant(Fp::from(1 << 32)))
                            + (c * Expression::Constant(Fp::from(1 << 16)))
                            + d)),
                // check 'b' is zero
                // s_over.clone() * (a_equals_b.expr() * (output.clone() - c)),
                s_over * (Expression::Constant(Fp::one()) - is_zero.expr()),
            ]
        });

        OverFlowCheckConfig {
            advice: [col_a, col_b_inv, col_b, col_c, col_d],
            instance,
            selector: [add_carry_selector, overflow_check_selector],
            is_zero,
        }
    }

    // Initial accumulator values from instance for expreiment
    pub fn assign_first_row(
        &self,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "first row",
            |mut region| {
                let b_cell = region.assign_advice_from_instance(
                    || "first acc[2]",
                    self.config.instance,
                    0,
                    self.config.advice[2],
                    0,
                )?;

                let c_cell = region.assign_advice_from_instance(
                    || "first acc[4]",
                    self.config.instance,
                    0,
                    self.config.advice[3],
                    0,
                )?;

                let d_cell = region.assign_advice_from_instance(
                    || "first acc[4]",
                    self.config.instance,
                    1,
                    self.config.advice[4],
                    0,
                )?;

                Ok((b_cell, c_cell, d_cell))
            },
        )
    }

    // fn add_carry<const MAX_BITS: u8>(
    //     &self,
    //     hi: AssignedCell<Fp, Fp>,
    //     lo: AssignedCell<Fp, Fp>,
    //     value: Value<Fp>,
    // ) -> (Fp, Fp) {
    //     let max_bits = Fp::from(1 << MAX_BITS);
    //     let mut sum = Fp::zero();

    //     // sum of all values
    //     value.as_ref().map(|f| sum = sum.add(f));
    //     hi.value().map(|f| sum = sum.add(&f.mul(&max_bits)));
    //     lo.value().map(|f| sum = sum.add(f));

    //     // Iterate sum of all
    //     let mut remains = sum;
    //     let mut carry_count = Fp::zero();
    //     while remains >= max_bits {
    //         remains = remains.sub(&max_bits);
    //         carry_count = carry_count.add(&Fp::one());
    //     }

    //     (carry_count, remains)
    // }

    pub fn assign_advice_row(
        &self,
        mut layouter: impl Layouter<Fp>,
        a: Value<Fp>,
        prev_b: AssignedCell<Fp, Fp>,
        prev_c: AssignedCell<Fp, Fp>,
        prev_d: AssignedCell<Fp, Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        let is_zero_chip = IsZeroChip::construct(self.config.is_zero.clone());
        layouter.assign_region(
            || "adivce row for accumulating",
            |mut region| {
                // enable hash selector
                self.config.selector[0].enable(&mut region, 1)?;
                self.config.selector[1].enable(&mut region, 1)?;

                let _ = prev_b.copy_advice(|| "prev_b", &mut region, self.config.advice[2], 0);
                let _ = prev_c.copy_advice(|| "prev_c", &mut region, self.config.advice[3], 0);
                let _ = prev_d.copy_advice(|| "prev_d", &mut region, self.config.advice[4], 0);

                // Assign new value to the cell inside the region
                region.assign_advice(|| "a", self.config.advice[0], 1, || a)?;

                let (hi, lo) = add_carry::<16>(a, prev_c.clone(), prev_d.clone());

                // assigning two columns of accumulating value
                let mut c_cell = region.assign_advice(
                    || "sum_hi",
                    self.config.advice[3],
                    1,
                    || Value::known(hi),
                )?;
                let d_cell = region.assign_advice(
                    || "sum_lo",
                    self.config.advice[4],
                    1,
                    || Value::known(lo),
                )?;

                let mut sum_overflow = Fp::zero();
                if hi >= Fp::from(1 << 16) {
                    let (ov, hi) = add_carry::<16>(
                        Value::known(Fp::zero()),
                        prev_b.clone(),
                        c_cell.clone(),
                    );
                    sum_overflow = ov;
                    c_cell = region.assign_advice(
                        || "sum_hi",
                        self.config.advice[3],
                        1,
                        || Value::known(hi),
                    )?;
                }

                let b_cell = region.assign_advice(
                    || "sum_overflow",
                    self.config.advice[2],
                    1,
                    || Value::known(sum_overflow),
                )?;

                // apply is_zero chip in here
                let _is_overflow = is_zero_chip.assign(&mut region, 1, Value::known(hi));

                Ok((b_cell, c_cell, d_cell))
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
