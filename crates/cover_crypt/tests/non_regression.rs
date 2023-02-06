use cosmian_cover_crypt::{test_utils::non_regression::NonRegressionTestVector, Error};

#[test]
fn test_generate_non_regression_vector() -> Result<(), Error> {
    let reg_vector = NonRegressionTestVector::new()?;

    std::fs::write(
        "../../target/non_regression_vector.json",
        serde_json::to_string(&reg_vector).unwrap(),
    )
    .unwrap();

    Ok(())
}
