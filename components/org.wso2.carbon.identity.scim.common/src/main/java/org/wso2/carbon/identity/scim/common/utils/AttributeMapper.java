/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim.common.utils;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.charon.core.attributes.Attribute;
import org.wso2.charon.core.attributes.ComplexAttribute;
import org.wso2.charon.core.attributes.DefaultAttributeFactory;
import org.wso2.charon.core.attributes.MultiValuedAttribute;
import org.wso2.charon.core.attributes.SimpleAttribute;
import org.wso2.charon.core.exceptions.CharonException;
import org.wso2.charon.core.exceptions.NotFoundException;
import org.wso2.charon.core.objects.AbstractSCIMObject;
import org.wso2.charon.core.objects.Group;
import org.wso2.charon.core.objects.SCIMObject;
import org.wso2.charon.core.objects.User;
import org.wso2.charon.core.schema.AttributeSchema;
import org.wso2.charon.core.schema.ResourceSchema;
import org.wso2.charon.core.schema.SCIMAttributeSchema;
import org.wso2.charon.core.schema.SCIMConstants;
import org.wso2.charon.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon.core.schema.SCIMSubAttributeSchema;
import org.wso2.charon.core.util.AttributeUtil;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for converting SCIM attributes in a SCIM object to
 * carbon claims and vice versa
 */
public class AttributeMapper {

    private static Log log = LogFactory.getLog(AttributeMapper.class);
    private static final boolean debug = log.isDebugEnabled();

    /**
     * Return claims as a map of <ClaimUri (which is mapped to SCIM attribute uri),ClaimValue>
     *
     * @param scimObject
     * @return
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws CharonException {
        Map<String, String> claimsMap = new HashMap<>();
        Map<String, Attribute> attributeList = scimObject.getAttributeList();
        for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
            Attribute attribute = attributeEntry.getValue();
            // if the attribute is password, skip it
            if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                continue;
            }

            claimsMap.putAll(convertAttributesToClaims(attribute));

        }
        return claimsMap;
    }

    private static Map<String, String> convertAttributesToClaims(Attribute attribute) throws CharonException {
        Map<String, String> claimsMap = new HashMap<>();

        if (attribute instanceof SimpleAttribute) {
            SimpleAttribute simpleAttribute = (SimpleAttribute) attribute;
            convertSimpleAttributeToClaims(simpleAttribute, claimsMap);
        } else if (attribute instanceof ComplexAttribute) {
            ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
            convertComplexAttributeToClaims(complexAttribute, claimsMap);
        } else if (attribute instanceof MultiValuedAttribute) {
            MultiValuedAttribute multiValuedAttribute = (MultiValuedAttribute) attribute;
            convertMultiValuedAttributeToClaims(multiValuedAttribute, claimsMap);
        } else {
            // TODO: add debug log and ignore
        }

        return claimsMap;
    }

    private static void convertSimpleAttributeToClaims(SimpleAttribute simpleAttribute, Map<String, String>
            claimsMap) throws CharonException {

        String attributeURI = simpleAttribute.getAttributeURI();
        String attributeName = simpleAttribute.getName();

        Object attributeValue = simpleAttribute.getValue();
        SCIMSchemaDefinitions.DataType attributeType = simpleAttribute.getDataType();

        if (attributeValue != null) {
            String stringAttributeValue = AttributeUtil.getStringValueOfAttribute(attributeValue, attributeType);
            claimsMap.put(attributeURI, stringAttributeValue);
            log.info("Adding simple attribute: " + attributeName + " with claim uri: " + attributeURI + " with value:" +
                    " " + stringAttributeValue);
        } else {
            //TODO: Add debug log and ignore
        }
    }

    private static void convertComplexAttributeToClaims(ComplexAttribute complexAttribute, Map<String, String>
            claimsMap) throws CharonException {

        String attributeName = complexAttribute.getName();

        // reading attributes list of the complex attribute
        Map<String, Attribute> attributes = null;
        if (MapUtils.isNotEmpty(complexAttribute.getSubAttributes())) {
            attributes = complexAttribute.getSubAttributes();
        } else if (MapUtils.isNotEmpty(complexAttribute.getAttributes())) {
            attributes = complexAttribute.getAttributes();
        }

        if (attributes != null) {
            for (Attribute attribute : attributes.values()) {
                claimsMap.putAll(convertAttributesToClaims(attribute));
                log.info("Adding subAttribute: " + attribute.getName() + " under complex attribute: " + attributeName);
            }
        } else {
            //TODO: Add debug log and ignore
        }

    }

    private static void convertMultiValuedAttributeToClaims(MultiValuedAttribute multiValuedAttribute, Map<String,
            String> claimsMap) throws CharonException {

        if (isSimpleMultiValuedAttribute(multiValuedAttribute)) {
            convertSimpleMultiValuedAttributeToClaims(multiValuedAttribute, claimsMap);
        } else if (isComplexMultiValuedAttribute(multiValuedAttribute)) {
            convertComplexMultiValuedAttributeToClaims(multiValuedAttribute, claimsMap);
        } else {
            //TODO: Add debug log
        }
    }

    private static boolean isSimpleMultiValuedAttribute(MultiValuedAttribute multiValuedAttribute) {

        List<String> attributeValues = multiValuedAttribute.getValuesAsStrings();
        return CollectionUtils.isNotEmpty(attributeValues);
    }

    private static boolean isComplexMultiValuedAttribute(MultiValuedAttribute multiValuedAttribute) {

        List<Attribute> subAttributeList = multiValuedAttribute.getValuesAsSubAttributes();
        return CollectionUtils.isNotEmpty(subAttributeList);
    }

    private static void convertSimpleMultiValuedAttributeToClaims(MultiValuedAttribute simpleMultiValuedAttribute,
                                                                  Map<String, String> claimsMap) {
        
        if (!isSimpleMultiValuedAttribute(simpleMultiValuedAttribute)) {
            return;
        }

        String attributeURI = simpleMultiValuedAttribute.getAttributeURI();
        String attributeName = simpleMultiValuedAttribute.getName();

        List<String> attributeValues = simpleMultiValuedAttribute.getValuesAsStrings();

        String values = null;
        for (String attributeValue : attributeValues) {
            if (values == null) {
                values = attributeValue;
            } else {
                // TODO: Use multi attribute seperator
                values += "," + attributeValue;
            }
        }
        claimsMap.put(attributeURI, values);
        log.info("Adding simple multivalued attribute: " + attributeName + " with claim uri: " + attributeURI + " " +
                "with value: " + values);
    }

    private static void convertComplexMultiValuedAttributeToClaims(MultiValuedAttribute complexMultiValuedAttribute,
                                                                   Map<String, String> claimsMap) throws
            CharonException {

        if (!isComplexMultiValuedAttribute(complexMultiValuedAttribute)) {
            return;
        }

        String attributeURI = complexMultiValuedAttribute.getAttributeURI();
        String attributeName = complexMultiValuedAttribute.getName();

        List<Attribute> subAttributeList = complexMultiValuedAttribute.getValuesAsSubAttributes();
        for (Attribute arrayElementAttribute : subAttributeList) {

            if (arrayElementAttribute instanceof ComplexAttribute) {

                ComplexAttribute arrayElementcomplexAttribute = (ComplexAttribute) arrayElementAttribute;
                String type = getType(arrayElementcomplexAttribute);
                if (type != null) {

                    Map<String, String> subClaimsMap = convertAttributesToClaims(arrayElementcomplexAttribute);

                    String value = getValue(arrayElementcomplexAttribute);
                    if (value != null) {
                        convertBasicComplexMultiValuedAttributeToClaims(attributeURI, type, value, claimsMap);
                    } else {
                        convertAdvancedComplexMultiValuedAttributeToClaims(subClaimsMap, attributeURI, type, claimsMap);
                    }
                } else {
                    log.error("Type cannot be null");
                    // Debug log (unexpected scenario)
                }
            } else {
                log.error("Attribute type should be a complex attribute");
                // Debug log (unexpected scenario)
            }
        }
    }

    private static void convertBasicComplexMultiValuedAttributeToClaims(String attributeURI, String type, String
            value, Map<String, String> claimsMap) {

        String modifiedAttributeURI = attributeURI + "." + type;
        claimsMap.put(modifiedAttributeURI, value);

        log.info("Modifying the claim uri from: " + attributeURI + " to: " + modifiedAttributeURI + " for value: " +
                value);
    }

    private static void convertAdvancedComplexMultiValuedAttributeToClaims(Map<String, String> subClaimsMap, String
            attributeURI, String type, Map<String, String> claimsMap) {

        Map<String, String> modifiedSubClaimsMap = new HashMap<>();

        for (Map.Entry<String, String> entry : subClaimsMap.entrySet()) {
            String subAttributeURI = entry.getKey();

            if (subAttributeURI == null) {
                if (!type.equals(entry.getValue())) {
                    log.error("Attribute URI cannot be null");
                    // TODO: Debug log (unexpected scenario)
                }
                continue;
            }

            String modifiedSubAttributeURI = subAttributeURI.replace(attributeURI, attributeURI + "#" + type);
            modifiedSubClaimsMap.put(modifiedSubAttributeURI, entry.getValue());

            log.info("Modifying the claim uri from: " + attributeURI + " to: " + modifiedSubAttributeURI + " for " +
                    "value: " + entry.getValue());
        }

        claimsMap.putAll(modifiedSubClaimsMap);
    }

    private static String getValue(ComplexAttribute complexAttribute) {

        Map<String, Attribute> subAttributes = complexAttribute.getSubAttributes();
        SimpleAttribute valueAttribute = (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);

        if (valueAttribute != null) {
            String typeValue = (String) valueAttribute.getValue();
            return typeValue;
        }

        return null;
    }

    private static String getType(ComplexAttribute complexAttribute) {

        Map<String, Attribute> subAttributes = complexAttribute.getSubAttributes();
        SimpleAttribute typeAttribute = (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);

        if (typeAttribute != null) {
            String typeValue = (String) typeAttribute.getValue();
            return typeValue;
        }

        return null;
    }

    /**
     * Construct the SCIM Object given the attribute URIs and attribute values of the object.
     *
     * @param attributes
     * @param scimObjectType
     * @return
     */
    public static SCIMObject constructSCIMObjectFromAttributes(Map<String, String> attributes,
                                                               int scimObjectType)
            throws CharonException, NotFoundException {
        SCIMObject scimObject = null;
        switch (scimObjectType) {
            case SCIMConstants.GROUP_INT:
                scimObject = new Group();
                log.debug("Building Group Object");
                break;
            case SCIMConstants.USER_INT:
                scimObject = new User();
                log.debug("Building User Object");
                break;
            default:
                break;
        }
        for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {

            if (debug) {
                log.debug("AttributeKey: " + attributeEntry.getKey() + " AttributeValue:" +
                        attributeEntry.getValue());
            }

            String attributeURI = attributeEntry.getKey();
            String[] attributeURIParts = attributeURI.split(":");
            String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
            String[] attributeNames = attributeNameString.split("\\.");

            if (attributeNames.length == 1) {
                //get attribute schema
                AttributeSchema attributeSchema = getAttributeSchema(attributeNames[0], scimObjectType);

                if (attributeSchema != null) {
                    //either simple valued or multi-valued with simple attributes
                    if (isMultivalued(attributeNames[0], scimObjectType)) {
                        //see whether multiple values are there
                        String value = attributeEntry.getValue();
                        String[] values = value.split(",");
                        //create attribute
                        MultiValuedAttribute multiValuedAttribute = new MultiValuedAttribute(
                                attributeSchema.getName());
                        //set values
                        multiValuedAttribute.setValuesAsStrings(Arrays.asList(values));
                        //set attribute in scim object
                        DefaultAttributeFactory.createAttribute(attributeSchema, multiValuedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multiValuedAttribute);

                    } else {
                        //convert attribute to relevant type
                        Object attributeValueObject = AttributeUtil.getAttributeValueFromString(
                                attributeEntry.getValue(), attributeSchema.getType());

                        //create attribute
                        SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[0],
                                attributeValueObject);
                        DefaultAttributeFactory.createAttribute(attributeSchema, simpleAttribute);
                        //set attribute in the SCIM object
                        ((AbstractSCIMObject) scimObject).setAttribute(simpleAttribute);
                    }
                }
            } else if (attributeNames.length == 2) {
                //get parent attribute name
                String parentAttributeName = attributeNames[0];
                //get parent attribute schema
                AttributeSchema parentAttributeSchema = getAttributeSchema(parentAttributeName,
                        scimObjectType);
                /*differenciate between sub attribute of Complex attribute and a Multivalued attribute
                with complex value*/
                if (isMultivalued(parentAttributeName, scimObjectType)) {
                    //create map with complex value (basic complex values)
                    Map<String, Object> complexValue = new HashMap<>();
                    complexValue.put(SCIMConstants.CommonSchemaConstants.TYPE, attributeNames[1]);
                    complexValue.put(SCIMConstants.CommonSchemaConstants.VALUE,
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    parentAttributeSchema.getType()));
                    //check whether parent multivalued attribute already exists
                    if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                        //create attribute value as complex value
                        MultiValuedAttribute multiValuedAttribute =
                                (MultiValuedAttribute) scimObject.getAttribute(parentAttributeName);
                        multiValuedAttribute.setComplexValue(complexValue);
                    } else {
                        //create the attribute and set it in the scim object
                        MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                                parentAttributeName);
                        multivaluedAttribute.setComplexValue(complexValue);
                        DefaultAttributeFactory.createAttribute(parentAttributeSchema, multivaluedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
                    }
                } else {
                    if (parentAttributeName != null && parentAttributeName.contains("#")) {
                        //multivalued complex value (advanced complex value)
                        String[] parentAttributeNames = parentAttributeName.split("#");
                        parentAttributeName = parentAttributeNames[0];
                        parentAttributeSchema = getAttributeSchema(parentAttributeName, scimObjectType);


                        String type = parentAttributeNames[1];
                        String attributeName = attributeNames[1];

                        Map<String, Object> complexValue = new HashMap<>();
                        complexValue.put(SCIMConstants.CommonSchemaConstants.TYPE, type);

                        //sub attribute of a complex attribute
                        AttributeSchema subAttributeSchema = getAttributeSchema(attributeName, scimObjectType);
                        complexValue.put(attributeName, AttributeUtil.getAttributeValueFromString(attributeEntry
                                .getValue(), subAttributeSchema.getType()));




                        //we assume sub attribute is simple attribute
                        SimpleAttribute simpleAttribute = new SimpleAttribute(attributeName,
                                AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                        subAttributeSchema.getType()));
                        simpleAttribute = (SimpleAttribute) DefaultAttributeFactory.createAttribute
                                (subAttributeSchema, simpleAttribute);

                        //check whether parent attribute exists.
                        MultiValuedAttribute multiValuedAttribute;
                        if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                            multiValuedAttribute = (MultiValuedAttribute) scimObject.getAttribute(parentAttributeName);


                            boolean isAttributeExists = false;
                            List<Attribute> subAttributeList = multiValuedAttribute.getValuesAsSubAttributes();
                            for (Attribute subAttribute : subAttributeList) {

                                if (subAttribute instanceof ComplexAttribute) {
                                    ComplexAttribute complexSubAttribute = (ComplexAttribute) subAttribute;

                                    String currentType = getType(complexSubAttribute);
                                    log.info("Type: " + currentType);

                                    if (type.equals(currentType)) {
                                        complexSubAttribute.setSubAttribute(simpleAttribute);
                                        isAttributeExists = true;
                                        break;
                                    }
                                }
                            }

                            if (!isAttributeExists) {
                                //create the attribute and set it in the scim object
                                Map<String, Attribute> subAttributesMap = new HashMap<>();
                                subAttributesMap.put(simpleAttribute.getName(), simpleAttribute);

                                SimpleAttribute typeAttribute = new SimpleAttribute("type", type);
                                typeAttribute = (SimpleAttribute)DefaultAttributeFactory.createAttribute
                                        (SCIMSchemaDefinitions.TYPE, typeAttribute);
                                subAttributesMap.put(typeAttribute.getName(), typeAttribute);

                                multiValuedAttribute.setComplexValueWithSetOfSubAttributes(subAttributesMap);
                            }
                        } else {
                            //create the attribute and set it in the scim object
                            multiValuedAttribute = new MultiValuedAttribute(parentAttributeName);

                            //create the attribute and set it in the scim object
                            Map<String, Attribute> subAttributesMap = new HashMap<>();
                            subAttributesMap.put(simpleAttribute.getName(), simpleAttribute);

                            SimpleAttribute typeAttribute = new SimpleAttribute("type", type);
                            typeAttribute = (SimpleAttribute)DefaultAttributeFactory.createAttribute
                                    (SCIMSchemaDefinitions.TYPE, typeAttribute);
                            subAttributesMap.put(typeAttribute.getName(), typeAttribute);


                            multiValuedAttribute.setComplexValueWithSetOfSubAttributes(subAttributesMap);
                            multiValuedAttribute = (MultiValuedAttribute) DefaultAttributeFactory.createAttribute
                                    (parentAttributeSchema, multiValuedAttribute);
                            ((AbstractSCIMObject) scimObject).setAttribute(multiValuedAttribute);
                        }


                    } else {
                        //sub attribute of a complex attribute
                        AttributeSchema subAttributeSchema = getAttributeSchema(attributeNames[1], scimObjectType);
                        //we assume sub attribute is simple attribute
                        SimpleAttribute simpleAttribute =
                                new SimpleAttribute(attributeNames[1],
                                        AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                                subAttributeSchema.getType()));
                        DefaultAttributeFactory.createAttribute(subAttributeSchema, simpleAttribute);
                        //check whether parent attribute exists.
                        if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                            ComplexAttribute complexAttribute =
                                    (ComplexAttribute) scimObject.getAttribute(parentAttributeName);
                            complexAttribute.setSubAttribute(simpleAttribute);
                        } else {
                            //create parent attribute and set sub attribute
                            ComplexAttribute complexAttribute = new ComplexAttribute(parentAttributeName);
                            complexAttribute.setSubAttribute(simpleAttribute);
                            DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);
                            ((AbstractSCIMObject) scimObject).setAttribute(complexAttribute);
                        }
                    }

                }
            } else if (attributeNames.length == 3) {
                //get immediate parent attribute name
                String immediateParentAttributeName = attributeNames[1];
                AttributeSchema immediateParentAttributeSchema = getAttributeSchema(immediateParentAttributeName,
                        scimObjectType);
                /*differenciate between sub attribute of Complex attribute and a Multivalued attribute
                with complex value*/
                if (isMultivalued(immediateParentAttributeName, scimObjectType)) {
                    //create map with complex value
                    Map<String, Object> complexValue = new HashMap<>();
                    complexValue.put(SCIMConstants.CommonSchemaConstants.TYPE, attributeNames[1]);
                    complexValue.put(SCIMConstants.CommonSchemaConstants.VALUE,
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    immediateParentAttributeSchema.getType()));
                    //check whether parent multivalued attribute already exists
                    if (((AbstractSCIMObject) scimObject).isAttributeExist(immediateParentAttributeName)) {
                        //create attribute value as complex value
                        MultiValuedAttribute multiValuedAttribute =
                                (MultiValuedAttribute) scimObject.getAttribute(immediateParentAttributeName);
                        multiValuedAttribute.setComplexValue(complexValue);
                    } else {
                        //create the attribute and set it in the scim object
                        MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                                immediateParentAttributeName);
                        multivaluedAttribute.setComplexValue(complexValue);
                        DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, multivaluedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
                    }
                } else {
                    //sub attribute of a complex attribute
                    AttributeSchema subAttributeSchema = getAttributeSchema(attributeNames[2], attributeNames[1], scimObjectType);
                    //we assume sub attribute is simple attribute
                    SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[2],
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    subAttributeSchema.getType()));
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, simpleAttribute);

                    // check if the super parent exist 
                    boolean superParentExist = ((AbstractSCIMObject) scimObject).isAttributeExist(attributeNames[0]);
                    if (superParentExist) {
                        ComplexAttribute superParentAttribute = (ComplexAttribute) ((AbstractSCIMObject) scimObject).getAttribute(attributeNames[0]);
                        // check if the immediate parent exist
                        boolean immediateParentExist = superParentAttribute.isSubAttributeExist(immediateParentAttributeName);
                        if (immediateParentExist) {
                            // both the parent and super parent exists
                            ComplexAttribute immediateParentAttribute = (ComplexAttribute) superParentAttribute.getSubAttribute(immediateParentAttributeName);
                            immediateParentAttribute.setSubAttribute(simpleAttribute);
                        } else { // immediate parent does not exist
                            ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                            immediateParentAttribute.setSubAttribute(simpleAttribute);
                            DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, immediateParentAttribute);
                            // created the immediate parent and now set to super
                            superParentAttribute.setSubAttribute(immediateParentAttribute);
                        }
                    } else { // now have to create both the super parent and immediate parent
                        // immediate first
                        ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                        immediateParentAttribute.setSubAttribute(simpleAttribute);
                        DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, immediateParentAttribute);
                        // now super parent
                        ComplexAttribute superParentAttribute = new ComplexAttribute(attributeNames[0]);
                        superParentAttribute.setSubAttribute(immediateParentAttribute);
                        AttributeSchema superParentAttributeSchema = getAttributeSchema(attributeNames[0], scimObjectType);
                        DefaultAttributeFactory.createAttribute(superParentAttributeSchema, superParentAttribute);
                        // now add the super to the scim object
                        ((AbstractSCIMObject) scimObject).setAttribute(superParentAttribute);
                    }
                }
            }
        }
        return scimObject;
    }

    private static boolean isMultivalued(String attributeName, int scimObjectType) {
        AttributeSchema attributeSchema = getAttributeSchema(attributeName, scimObjectType);
        if (attributeSchema != null) {
            return attributeSchema.getMultiValued();
        }
        return false;
    }

    private static AttributeSchema getAttributeSchema(String attributeName, int scimObjectType) {
        return getAttributeSchema(attributeName, null, scimObjectType);
    }

    private static AttributeSchema getAttributeSchema(String attributeName, String parentAttributeName, int scimObjectType) {
        ResourceSchema resourceSchema = getResourceSchema(scimObjectType);
        if (resourceSchema != null) {
            List<AttributeSchema> attributeSchemas = resourceSchema.getAttributesList();
            for (AttributeSchema attributeSchema : attributeSchemas) {
                if (attributeName.equals(attributeSchema.getName())) {
                    if (parentAttributeName == null ||
                            attributeSchema.getURI().contains(parentAttributeName)) {
                        return attributeSchema;
                    }
                }
                //check for sub attributes
                List<SCIMSubAttributeSchema> subAttributeSchemas =
                        ((SCIMAttributeSchema) attributeSchema).getSubAttributes();
                if (CollectionUtils.isNotEmpty(subAttributeSchemas)) {
                    for (SCIMSubAttributeSchema subAttributeSchema : subAttributeSchemas) {
                        if (attributeName.equals(subAttributeSchema.getName())) {
                            if (parentAttributeName == null ||
                                    subAttributeSchema.getURI().contains(parentAttributeName)) {
                                return subAttributeSchema;
                            }
                        }
                    }
                }
                // check for attributes of the attribute
                List<SCIMAttributeSchema> attribSchemas = ((SCIMAttributeSchema) attributeSchema).getAttributes();
                if (CollectionUtils.isNotEmpty(attribSchemas)) {
                    for (SCIMAttributeSchema attribSchema : attribSchemas) {
                        // if the attribute a simple attribute
                        if (attributeName.equals(attribSchema.getName())) {
                            return attribSchema;
                        }
                        // if the attribute a complex attribute having sub attributes
                        //check for sub attributes
                        List<SCIMSubAttributeSchema> subSubAttribSchemas =
                                ((SCIMAttributeSchema) attribSchema).getSubAttributes();
                        if (CollectionUtils.isNotEmpty(subSubAttribSchemas)) {
                            for (SCIMSubAttributeSchema subSubAttribSchema : subSubAttribSchemas) {
                                if (attributeName.equals(subSubAttribSchema.getName())) {
                                    if (parentAttributeName == null ||
                                            subSubAttribSchema.getURI().contains(parentAttributeName)) {
                                        return subSubAttribSchema;
                                    }
                                }
                            }
                        }
                        // check for attributes
                        List<SCIMAttributeSchema> attributSchemas = ((SCIMAttributeSchema) attribSchema).getAttributes();
                        if (CollectionUtils.isNotEmpty(attributSchemas)) {
                            for (SCIMAttributeSchema atttribSchema : attributSchemas) {
                                if (attributeName.equals(atttribSchema.getName())) {
                                    if (parentAttributeName == null ||
                                            atttribSchema.getURI().contains(parentAttributeName)) {
                                        return atttribSchema;
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
        return null;
    }

    private static ResourceSchema getResourceSchema(int scimObjectType) {
        ResourceSchema resourceSchema = null;
        switch (scimObjectType) {
            case SCIMConstants.USER_INT:
                resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
                break;
            case SCIMConstants.GROUP_INT:
                resourceSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
                break;
            default:
                break;
        }
        return resourceSchema;
    }
//TODO: get the role list as well.
}
