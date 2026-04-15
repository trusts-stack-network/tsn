use tsn_crypto::signature::{Groth16Proof, verify_groth16};
use tsn_crypto::curve::bn254::{G1Affine, G2Affine, Fq};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_invalid_curve_resistance(
        a_g1 in arb_g1_invalid(),
        b_g2 in arb_g2_invalid(),
        c_g1 in arb_g1_invalid(),
        public_inputs in arb_public_inputs()
    ) {
        let proof = Groth16Proof { a: a_g1, b: b_g2, c: c_g1 };
        
        // Doit fail proprement, pas paniquer
        let result = verify_groth16(&proof, &public_inputs);
        
        // Doit rejeter les points invalids
        prop_assert!(result.is_err());
        
        // Check that l'error est appropriee
        match result {
            Err(e) => {
                prop_assert!(e.to_string().contains("invalid curve point"));
            },
            Ok(_) => panic!("Invalid curve point acceptee!"),
        }
    }
}

fn arb_g1_invalid() -> impl Strategy<Value = G1Affine> {
    // Points hors courbe, ordre incorrect, coordata non-valides
    prop_oneof![
        // Point a l'infini (doit be rejete sauf si explicitement autorise)
        Just(G1Affine::identity()),
        // Coordata non-valides
        (0u64..1000).prop_map(|_| {
            let mut g = G1Affine::generator();
            g.x = Fq::from(12345u64); // Coordonnee invalid
            g
        }),
        // Points d'ordre incorrect
        (1u64..1000).prop_map(|i| {
            let g = G1Affine::generator();
            g.mul(i).into_affine()
        }),
    ]
}

fn arb_g2_invalid() -> impl Strategy<Value = G2Affine> {
    // Similaire pour G2
    prop_oneof![
        Just(G2Affine::identity()),
        (0u64..1000).prop_map(|_| {
            let mut g = G2Affine::generator();
            g.x.c0 = Fq::from(12345u64);
            g
        }),
    ]
}

fn arb_public_inputs() -> impl Strategy<Value = Vec<Fq>> {
    prop::collection::vec(any::<u64>().prop_map(Fq::from), 0..10)
}