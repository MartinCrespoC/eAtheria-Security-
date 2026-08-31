/**
 * False Positive Patterns for SAP (ABAP + SAP Fiori/UI5)
 * Common SAP development patterns that are not actual vulnerabilities
 */

export const SAP_FALSE_POSITIVES = [
  // === ABAP: Output & Logging ===
  {
    language: "abap",
    pattern: "WRITE\\s*[:/]",
    description: "ABAP WRITE statement for output",
    reason: "WRITE is the standard ABAP output statement for reports and lists, not an injection vector",
    context: "development",
    cweIds: ["CWE-532", "CWE-117"],
    examples: [
      "WRITE: / lv_message.",
      "WRITE / 'Processing complete'.",
    ],
  },
  {
    language: "abap",
    pattern: "MESSAGE\\s+[A-Z]\\d+",
    description: "ABAP MESSAGE statement",
    reason: "Standard ABAP message handling for user feedback and error reporting",
    context: "error-handling",
    cweIds: ["CWE-209", "CWE-532"],
    examples: [
      "MESSAGE E001(ZMM) WITH lv_material.",
      "MESSAGE S000(00) WITH 'Saved successfully'.",
    ],
  },
  {
    language: "abap",
    pattern: "BAL_LOG|BAL_DSP|SLFG|SLFV",
    description: "SAP Business Application Log (BAL)",
    reason: "Standard SAP logging framework (transaction SLG1), not information exposure",
    context: "logging",
    cweIds: ["CWE-532"],
    examples: [
      "CALL FUNCTION 'BAL_LOG_CREATE'.",
      "CALL FUNCTION 'BAL_DSP_LOG_DISPLAY'.",
    ],
  },

  // === ABAP: SQL & Database ===
  {
    language: "abap",
    pattern: "SELECT.*INTO\\s+(TABLE\\s+)?[A-Z]",
    description: "ABAP SELECT with INTO clause",
    reason: "Standard Open SQL with typed target variables. ABAP Open SQL is inherently parameterized",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      "SELECT * FROM mara INTO TABLE lt_materials WHERE matnr = lv_matnr.",
      "SELECT SINGLE * FROM vbak INTO ls_header WHERE vbeln = lv_vbeln.",
    ],
  },
  {
    language: "abap",
    pattern: "FOR ALL ENTRIES IN",
    description: "ABAP FOR ALL ENTRIES optimization",
    reason: "Standard ABAP bulk-select pattern for performance, not dynamic SQL",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      "SELECT * FROM mard FOR ALL ENTRIES IN lt_materials WHERE matnr = lt_materials-matnr.",
    ],
  },
  {
    language: "abap",
    pattern: "EXEC\\s+SQL.*EXEC\\s+SQL",
    description: "Native SQL with EXEC SQL blocks",
    reason: "When used with host variables (:lv_var), native SQL is parameterized and safe",
    context: "safe-sql",
    cweIds: ["CWE-89"],
    examples: [
      "EXEC SQL. SELECT name INTO :lv_name FROM users WHERE id = :lv_id ENDEXEC.",
    ],
  },

  // === ABAP: Authorization ===
  {
    language: "abap",
    pattern: "AUTHORITY-CHECK\\s+OBJECT",
    description: "SAP Authorization Check",
    reason: "Standard SAP authorization verification using authorization objects",
    context: "framework",
    cweIds: ["CWE-862", "CWE-863"],
    examples: [
      "AUTHORITY-CHECK OBJECT 'M_MATE_STA' ID 'ACTVT' FIELD '03'.",
      "AUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' FIELD sy-tcode.",
    ],
  },
  {
    language: "abap",
    pattern: "SAP\\s*GUI|SAPGUI|sap\\.gui",
    description: "SAP GUI framework references",
    reason: "Standard SAP GUI framework for user interaction",
    context: "framework",
    cweIds: ["CWE-79"],
    examples: [
      "CALL FUNCTION 'SAPGUI_PROGRESS_INDICATOR'.",
      "cl_gui_frontend_services=>file_open_dialog( ).",
    ],
  },

  // === ABAP: RFC & BAPI ===
  {
    language: "abap",
    pattern: "CALL\\s+FUNCTION\\s+'(BAPI_|RFC_)",
    description: "BAPI/RFC function module calls",
    reason: "Standard SAP Business APIs and Remote Function Calls are validated interfaces",
    context: "framework",
    cweIds: ["CWE-918", "CWE-915"],
    examples: [
      "CALL FUNCTION 'BAPI_MATERIAL_GETLIST'.",
      "CALL FUNCTION 'RFC_READ_TABLE' DESTINATION lv_dest.",
    ],
  },
  {
    language: "abap",
    pattern: "CALL\\s+FUNCTION\\s+'",
    description: "ABAP function module call",
    reason: "Standard ABAP function module invocation with typed parameters",
    context: "framework",
    cweIds: ["CWE-915"],
    examples: [
      "CALL FUNCTION 'CONVERSION_EXIT_ALPHA_INPUT'.",
      "CALL FUNCTION 'DATE_CONVERT_TO_FACTORYDATE'.",
    ],
  },
  {
    language: "abap",
    pattern: "DESTINATION\\s+['A-Z]",
    description: "RFC destination specification",
    reason: "RFC destinations are configured in SM59 by administrators, not user-controlled",
    context: "configuration",
    cweIds: ["CWE-918"],
    examples: [
      "CALL FUNCTION 'Z_GET_DATA' DESTINATION 'SAP_PROD_01'.",
      "CREATE OBJECT lo_proxy EXPORTING destination = lv_rfc_dest.",
    ],
  },

  // === ABAP: Internal Tables & Data ===
  {
    language: "abap",
    pattern: "APPEND\\s+(INITIAL\\s+LINE\\s+)?(OF|TO)",
    description: "ABAP internal table APPEND",
    reason: "Standard internal table manipulation, not code injection",
    context: "data-manipulation",
    cweIds: ["CWE-915"],
    examples: [
      "APPEND ls_item TO lt_items.",
      "APPEND INITIAL LINE TO lt_data ASSIGNING <fs_line>.",
    ],
  },
  {
    language: "abap",
    pattern: "MODIFY\\s+(TABLE\\s+)?[a-z]",
    description: "ABAP MODIFY internal table",
    reason: "Standard internal table row modification",
    context: "data-manipulation",
    cweIds: ["CWE-915"],
    examples: [
      "MODIFY TABLE lt_items FROM ls_item.",
      "MODIFY lt_data FROM ls_row INDEX lv_index.",
    ],
  },
  {
    language: "abap",
    pattern: "FIELD-SYMBOLS?\\s*<",
    description: "ABAP field symbols",
    reason: "Standard ABAP memory reference mechanism for performance optimization",
    context: "language-feature",
    cweIds: ["CWE-822", "CWE-476"],
    examples: [
      "FIELD-SYMBOLS <fs_item> TYPE ty_item.",
      "ASSIGN COMPONENT 'MATNR' OF STRUCTURE ls_data TO <fs_field>.",
    ],
  },

  // === ABAP: Enhancements & Exits ===
  {
    language: "abap",
    pattern: "ENHANCEMENT[- ](POINT|SECTION)|BADI|BAdI",
    description: "SAP Enhancement framework",
    reason: "Standard SAP enhancement points and Business Add-Ins for extensibility",
    context: "framework",
    cweIds: ["CWE-915", "CWE-94"],
    examples: [
      "ENHANCEMENT-POINT z_enh_point SPOTS es_saplv60a.",
      "CALL BADI lo_badi->process( ).",
    ],
  },
  {
    language: "abap",
    pattern: "USER-EXIT|EXIT\\s+FROM",
    description: "SAP user exits",
    reason: "Standard SAP modification points in SAP-delivered programs",
    context: "framework",
    cweIds: ["CWE-94"],
    examples: [
      "EXIT FROM STEP-LOOP.",
      "INCLUDE ZXVVAU01.  \" User exit include",
    ],
  },

  // === ABAP: IDoc & ALE ===
  {
    language: "abap",
    pattern: "IDOC|MASTER_IDOC|EDI_",
    description: "SAP IDoc/EDI processing",
    reason: "Standard SAP Intermediate Document processing for ALE/EDI integration",
    context: "framework",
    cweIds: ["CWE-502", "CWE-20"],
    examples: [
      "CALL FUNCTION 'MASTER_IDOC_DISTRIBUTE'.",
      "CALL FUNCTION 'EDI_DOCUMENT_DEQUEUE_LATER'.",
    ],
  },
  {
    language: "abap",
    pattern: "RECEIVE\\s+IDOC|PROCESS\\s+IDOC",
    description: "IDoc inbound processing",
    reason: "Standard SAP IDoc inbound processing with type validation",
    context: "framework",
    cweIds: ["CWE-502"],
    examples: [
      "FUNCTION z_idoc_input_ordmas. PROCESS 970.",
      "RECEIVE IDOC WITH TYPE 'ORDMAS05'.",
    ],
  },

  // === ABAP: ALV & Reporting ===
  {
    language: "abap",
    pattern: "REUSE_ALV|CL_SALV|CL_GUI_ALV",
    description: "SAP ALV Grid/List display",
    reason: "Standard SAP reporting output framework (ABAP List Viewer)",
    context: "framework",
    cweIds: ["CWE-79"],
    examples: [
      "CALL FUNCTION 'REUSE_ALV_GRID_DISPLAY'.",
      "cl_salv_table=>factory( IMPORTING r_salv_table = lo_alv ).",
    ],
  },

  // === ABAP: Security patterns that are SAFE ===
  {
    language: "abap",
    pattern: "HASH\\s*=\\s*['\"]SHA|cl_abap_hmac|CALCULATE_HASH",
    description: "SAP standard hashing",
    reason: "SAP standard cryptographic hashing classes and function modules",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-328"],
    examples: [
      "CALL FUNCTION 'CALCULATE_HASH_FOR_CHAR' EXPORTING alg = 'SHA256'.",
      "cl_abap_hmac=>calculate_hmac_for_char( ).",
    ],
  },
  {
    language: "abap",
    pattern: "SSF_KRN_ENVELOPE|CL_ABAP_ENCRYPTION|SECSTORE",
    description: "SAP Secure Store / Encryption",
    reason: "SAP standard encryption and secure storage mechanisms",
    context: "cryptography",
    cweIds: ["CWE-327", "CWE-326"],
    examples: [
      "CALL FUNCTION 'SSF_KRN_ENVELOPE'.",
      "cl_abap_encryption=>encrypt_data( ).",
    ],
  },

  // === ABAP: Transaction & Program flow ===
  {
    language: "abap",
    pattern: "CALL\\s+TRANSACTION|LEAVE\\s+TO\\s+TRANSACTION",
    description: "SAP transaction calls",
    reason: "Standard SAP transaction navigation, controlled by authorization objects",
    context: "framework",
    cweIds: ["CWE-862"],
    examples: [
      "CALL TRANSACTION 'MM03' WITH AUTHORITY-CHECK.",
      "LEAVE TO TRANSACTION 'VA02'.",
    ],
  },
  {
    language: "abap",
    pattern: "SUBMIT\\s+[A-Z]",
    description: "ABAP SUBMIT statement",
    reason: "Standard ABAP program submission with parameter passing",
    context: "framework",
    cweIds: ["CWE-94"],
    examples: [
      "SUBMIT zfi_report WITH p_bukrs = lv_bukrs AND RETURN.",
      "SUBMIT rsbdcsub WITH mappe = lv_mappe.",
    ],
  },

  // === SAP UI5 / Fiori (JavaScript-based) ===
  {
    language: "javascript",
    pattern: "sap\\.ui\\.(core|model|view|commons)",
    description: "SAP UI5 framework API calls",
    reason: "Standard SAP UI5 framework methods with built-in XSS protection and data binding",
    context: "framework",
    cweIds: ["CWE-79"],
    examples: [
      'sap.ui.getCore().byId("myControl")',
      'new sap.m.Table({ items: { path: "/items" } })',
    ],
  },
  {
    language: "javascript",
    pattern: "jQuery\\.sap\\.|sap\\.fiori|sap\\.ushell",
    description: "SAP Fiori Launchpad / jQuery.sap APIs",
    reason: "Standard SAP Fiori framework APIs with built-in security controls",
    context: "framework",
    cweIds: ["CWE-79", "CWE-94"],
    examples: [
      'jQuery.sap.require("sap.m.MessageBox")',
      'sap.ushell.Container.getService("CrossApplicationNavigation")',
    ],
  },
  {
    language: "javascript",
    pattern: "ODataModel|JSONModel|XMLModel",
    description: "SAP UI5 data models",
    reason: "Standard SAP UI5 model classes with built-in data validation and escaping",
    context: "framework",
    cweIds: ["CWE-79", "CWE-89"],
    examples: [
      'var oModel = new sap.ui.model.odata.v2.ODataModel("/sap/opu/odata/sap/ZAPI_SRV")',
      'var oModel = new sap.ui.model.json.JSONModel({ items: [] })',
    ],
  },
  {
    language: "javascript",
    pattern: "sap\\.ui\\.model\\.Filter|FilterOperator",
    description: "SAP UI5 OData filters",
    reason: "Server-side filtering via OData protocol, parameters are URL-encoded by framework",
    context: "safe-sql",
    cweIds: ["CWE-89", "CWE-943"],
    examples: [
      'new sap.ui.model.Filter("matnr", sap.ui.model.FilterOperator.EQ, lvValue)',
      'oBinding.filter([new Filter("status", FilterOperator.EQ, "A")])',
    ],
  },
  {
    language: "javascript",
    pattern: "sap\\.ui\\.core\\.security|encodeHTML|encodeURL|encodeJS",
    description: "SAP UI5 encoding utilities",
    reason: "SAP UI5 built-in encoding functions that properly escape output",
    context: "safe-encoding",
    cweIds: ["CWE-79"],
    examples: [
      'sap.ui.core.security.encodeHTML(userInput)',
      'jQuery.sap.encodeURL(paramValue)',
    ],
  },

  // === SAP: CDS Views & RAP ===
  {
    language: "abap",
    pattern: "@AbapCatalog|@AccessControl|@EndUserText",
    description: "ABAP CDS View annotations",
    reason: "Standard Core Data Services annotations with built-in access control",
    context: "framework",
    cweIds: ["CWE-862"],
    examples: [
      "@AbapCatalog.sqlViewName: 'ZV_MATERIAL'",
      "@AccessControl.authorizationCheck: #CHECK",
    ],
  },
  {
    language: "abap",
    pattern: "DCL\\s+|@MappingRole|DEFINE\\s+ROLE",
    description: "ABAP CDS DCL (Data Control Language)",
    reason: "Standard SAP authorization framework for CDS views",
    context: "framework",
    cweIds: ["CWE-862", "CWE-863"],
    examples: [
      "DEFINE ROLE z_role_material AS SELECT FROM z_material.",
      "@MappingRole: true",
    ],
  },

  // === SAP: OData Services ===
  {
    language: "abap",
    pattern: "/IWBEP/|CL_SADL|SADL",
    description: "SAP OData/Gateway framework",
    reason: "Standard SAP Gateway OData service framework with built-in CSRF protection",
    context: "framework",
    cweIds: ["CWE-352", "CWE-862"],
    examples: [
      "CLASS zcl_zapi_dpc_ext DEFINITION INHERITING FROM /iwbep/cl_mgw_push_abs_data.",
      "CALL METHOD /iwbep/if_mgw_appl_srv_runtime~get_entityset.",
    ],
  },
  {
    language: "abap",
    pattern: "CSRF|X-CSRF-Token|sap-contextid",
    description: "SAP CSRF token handling",
    reason: "Standard SAP Gateway CSRF protection mechanism for OData services",
    context: "framework",
    cweIds: ["CWE-352"],
    examples: [
      "lv_token = io_http_request->get_header_field( 'x-csrf-token' ).",
      "SET HEADER FIELD 'X-CSRF-Token' VALUE 'Fetch'.",
    ],
  },
];
