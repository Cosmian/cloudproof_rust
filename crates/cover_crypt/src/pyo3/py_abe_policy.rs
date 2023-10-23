use std::result::Result;

use cosmian_cover_crypt::abe_policy::{
    Attribute as AttributeRust, DimensionBuilder, EncryptionHint, Policy as PolicyRust,
};
use pyo3::{
    exceptions::{PyException, PyTypeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyList},
};

/// An attribute in a policy group is characterized by the axis policy name
/// and its unique name within this axis.
///
/// Args:
///     axis (str): policy axis the attributes belongs to
///     name (str): unique attribute name within this axis
#[pyclass]
#[derive(Clone)]
pub struct Attribute(AttributeRust);

#[pymethods]
impl Attribute {
    #[new]
    pub fn new(axis: &str, name: &str) -> Self {
        Self(AttributeRust::new(axis, name))
    }

    /// Gets the corresponding axis of the attribute.
    ///
    /// Returns:
    ///     str
    pub fn get_axis(&self) -> &str {
        &self.0.dimension
    }

    /// Gets the attribute name.
    ///
    /// Returns:
    ///     str
    pub fn get_name(&self) -> &str {
        &self.0.name
    }

    /// Creates a string representation of the attribute
    ///
    /// Returns:
    ///     str
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }

    /// Creates a policy attribute from a string representation
    ///
    /// Args:
    ///     string (str): Attribute in string format
    ///
    /// Returns:
    ///     Attribute
    #[staticmethod]
    pub fn from_string(string: &str) -> PyResult<Self> {
        match AttributeRust::try_from(string) {
            Ok(inner) => Ok(Self(inner)),
            Err(e) => Err(PyException::new_err(e.to_string())),
        }
    }
}

/// Defines an unique policy axis with the given name and attribute names.
/// If `hierarchical` is set to `true`, the axis is defined as hierarchical.
///
/// Args:
///         name (str): axis name
///         attributes (List[str], bool): name of the attributes on this axis
/// and encryption hint
///         hierarchical (bool): set the axis to be hierarchical
#[pyclass]
pub struct PolicyAxis(DimensionBuilder);

#[pymethods]
impl PolicyAxis {
    #[new]
    fn new(name: &str, attributes: &PyList, hierarchical: bool) -> PyResult<Self> {
        // attributes use Classic encryption if not specified
        let attributes = attributes
            .into_iter()
            .map(|attr| {
                if let Ok(name) = attr.extract::<&str>() {
                    Ok((name, EncryptionHint::Classic))
                } else if let Ok((name, is_hybridized)) = attr.extract::<(&str, bool)>() {
                    if is_hybridized {
                        Ok((name, EncryptionHint::Hybridized))
                    } else {
                        Ok((name, EncryptionHint::Classic))
                    }
                } else {
                    Err(PyValueError::new_err(
                        "Attributes should be of type List[str] or List[Tuple[str, bool]].",
                    ))
                }
            })
            .collect::<Result<_, _>>()?;

        Ok(Self(DimensionBuilder::new(name, attributes, hierarchical)))
    }

    /// Returns the number of attributes belonging to this axis.
    ///
    /// Returns:
    ///     int
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check whether the attribute list is empty
    ///
    /// Returns:
    ///     bool
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Gets axis name.
    ///
    /// Returns:
    ///     str
    pub fn get_name(&self) -> &str {
        &self.0.name
    }

    /// Gets the list of attributes in the axis.
    ///
    /// Returns:
    ///     List[str]
    pub fn get_attributes(&self) -> Vec<(String, bool)> {
        self.0
            .attributes_properties
            .iter()
            .map(|attribute_properties| {
                (
                    attribute_properties.name.clone(),
                    attribute_properties.encryption_hint == EncryptionHint::Hybridized,
                )
            })
            .collect()
    }

    /// Checks whether the axis is hierarchical.
    ///
    /// Returns:
    ///     bool
    pub fn is_hierarchical(&self) -> bool {
        self.0.hierarchical
    }

    /// Creates a string representation of the policy axis
    ///
    /// Returns:
    ///     str
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        format!(
            "{}: {:?}, hierarchical: {}",
            &self.0.name, &self.0.attributes_properties, &self.0.hierarchical
        )
    }
}

/// A policy is a set of policy axes. A fixed number of attribute creations
/// (revocations + additions) is allowed.
#[pyclass]
pub struct Policy(pub(super) PolicyRust);

#[pymethods]
impl Policy {
    /// Generates a new policy object with the given number of attribute
    /// creations (revocation + addition) allowed.
    /// Default maximum of attribute creations is u32::MAX
    #[new]
    fn new() -> Self {
        Self(PolicyRust::new())
    }

    /// Adds the given policy axis to the policy.
    pub fn add_axis(&mut self, axis: &PolicyAxis) -> PyResult<()> {
        self.0
            .add_dimension(axis.0.clone())
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Removes the given axis from the policy.
    pub fn remove_axis(&mut self, axis_name: &str) -> PyResult<()> {
        self.0
            .remove_dimension(axis_name)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Adds the given attribute to the policy.
    pub fn add_attribute(&mut self, attribute: Attribute, is_hybridized: bool) -> PyResult<()> {
        self.0
            .add_attribute(attribute.0, EncryptionHint::new(is_hybridized))
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Removes the given attribute from the policy
    /// Encrypting and decrypting for this attribute will no longer be possible
    /// once the keys are updated.
    pub fn remove_attribute(&mut self, attribute: &Attribute) -> PyResult<()> {
        self.0
            .remove_attribute(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(&mut self, attribute: &Attribute) -> PyResult<()> {
        self.0
            .disable_attribute(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Changes the name of an attribute.
    pub fn rename_attribute(&mut self, attribute: &Attribute, new_name: &str) -> PyResult<()> {
        self.0
            .rename_attribute(&attribute.0, new_name)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Rotates an attribute, changing its underlying value with an unused
    /// value.
    pub fn rotate(&mut self, attribute: &Attribute) -> PyResult<()> {
        self.0
            .rotate(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Removes old rotations id of an attribute.
    pub fn clear_old_attribute_values(&mut self, attr: &Attribute) -> PyResult<()> {
        self.0
            .clear_old_attribute_values(&attr.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Returns the list of Attributes of this Policy.
    pub fn attributes(&self) -> Vec<Attribute> {
        self.0.attributes().into_iter().map(Attribute).collect()
    }

    /// Returns the list of all attributes values given to this Attribute
    /// over the time after rotations. The current value is returned first
    pub fn attribute_values(&self, attribute: &Attribute) -> PyResult<Vec<u32>> {
        self.0
            .attribute_values(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Retrieves the current value of an attribute.
    pub fn attribute_current_value(&self, attribute: &Attribute) -> PyResult<u32> {
        self.0
            .attribute_current_value(&attribute.0)
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Formats policy to json.
    pub fn to_bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        serde_json::to_vec(&self.0)
            .map(|bytes| PyBytes::new(py, bytes.as_slice()).into())
            .map_err(|e| PyException::new_err(e.to_string()))
    }

    /// Reads policy from bytes.
    #[staticmethod]
    pub fn from_bytes(bytes: &PyBytes) -> PyResult<Self> {
        serde_json::from_slice(bytes.as_bytes())
            .map(Self)
            .map_err(|e| PyTypeError::new_err(format!("Error deserializing attributes: {e}")))
    }

    /// Returns a string representation of the policy.
    fn __repr__(&self) -> String {
        format!("{}", &self.0)
    }

    /// Performs deep copy of the policy.
    pub fn deep_copy(&self) -> Self {
        Self(self.0.clone())
    }
}
