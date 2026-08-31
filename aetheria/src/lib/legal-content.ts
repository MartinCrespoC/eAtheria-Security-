import type { Locale } from "@/lib/i18n/types";

export type LegalDocId = "terms" | "privacy" | "security";

export interface LegalSection {
  heading: string;
  body: string[];
}

export interface LegalDoc {
  title: string;
  updated: string;
  intro: string;
  sections: LegalSection[];
}

export const LEGAL_CONTENT: Record<LegalDocId, Record<Locale, LegalDoc>> = {
  terms: {
    es: {
      title: "Términos y Condiciones de Servicio",
      updated: "Última actualización: 3 de agosto de 2026",
      intro:
        "Estos Términos y Condiciones de Servicio (los \"Términos\") constituyen un contrato legalmente vinculante entre usted (el \"Cliente\", \"usted\" o el \"Usuario\") y EATHERIA Security (\"EATHERIA\", \"nosotros\" o \"la Empresa\"), operador de la plataforma disponible en eatheria.com (la \"Plataforma\"). AL CREAR UNA CUENTA, MARCAR LA CASILLA DE ACEPTACIÓN O UTILIZAR LA PLATAFORMA, USTED DECLARA QUE HA LEÍDO, ENTENDIDO Y ACEPTA ESTOS TÉRMINOS EN SU TOTALIDAD, ASÍ COMO NUESTRA POLÍTICA DE PRIVACIDAD. SI NO ESTÁ DE ACUERDO, NO DEBE REGISTRARSE NI UTILIZAR LA PLATAFORMA.",
      sections: [
        {
          heading: "1. Aceptación y capacidad legal",
          body: [
            "Al registrarse, usted declara y garantiza que: (a) tiene al menos 18 años de edad; (b) tiene capacidad legal para celebrar contratos vinculantes; (c) si se registra en nombre de una empresa u organización, tiene autoridad para obligar a dicha entidad a estos Términos, en cuyo caso \"usted\" se referirá a esa entidad; y (d) toda la información proporcionada durante el registro es veraz, exacta y completa.",
            "La aceptación se perfecciona mediante el marcado de la casilla de aceptación durante el registro. EATHERIA registra y conserva la fecha, hora y dirección IP de cada aceptación como evidencia contractual.",
          ],
        },
        {
          heading: "2. Descripción del servicio",
          body: [
            "EATHERIA es una plataforma de seguridad de aplicaciones que proporciona análisis estático de código (SAST), análisis dinámico (DAST), análisis de composición de software (SCA), detección de secretos, generación de SBOM y reportes de cumplimiento (OWASP, CWE, PCI DSS, NIST), con validación asistida por inteligencia artificial.",
            "El servicio se proporciona como software como servicio (SaaS) por suscripción. Nos reservamos el derecho de modificar, mejorar, suspender o descontinuar funcionalidades con notificación razonable, sin que ello genere derecho a compensación alguna.",
          ],
        },
        {
          heading: "3. Naturaleza orientativa de los resultados — Sin garantía de seguridad",
          body: [
            "USTED RECONOCE Y ACEPTA EXPRESAMENTE QUE: (a) los análisis de seguridad, incluyendo los validados por inteligencia artificial, son herramientas de apoyo a la decisión y NO constituyen una garantía, certificación ni aseguramiento de que el software analizado sea seguro o esté libre de vulnerabilidades; (b) ninguna herramienta de análisis automatizado puede detectar la totalidad de las vulnerabilidades existentes; (c) pueden existir falsos positivos y falsos negativos; y (d) la seguridad de sus sistemas es y seguirá siendo SU RESPONSABILIDAD EXCLUSIVA.",
            "Los resultados, puntuaciones, benchmarks, hallazgos, severidades y recomendaciones emitidos por la Plataforma tienen carácter meramente informativo y orientativo. EATHERIA no será responsable de brechas de seguridad, pérdida de datos, ataques, explotación de vulnerabilidades (detectadas o no) ni de ningún daño derivado de decisiones tomadas con base en los resultados de la Plataforma.",
          ],
        },
        {
          heading: "4. Cuentas, credenciales y responsabilidad",
          body: [
            "Usted es responsable de mantener la confidencialidad de sus credenciales de acceso, claves API y tokens, y de toda actividad que ocurra bajo su cuenta. Debe notificarnos de inmediato cualquier uso no autorizado. EATHERIA no será responsable de pérdidas derivadas del uso no autorizado de sus credenciales cuando usted no haya implementado las medidas de seguridad disponibles (como la autenticación de dos factores).",
            "Nos reservamos el derecho de suspender o cancelar cuentas que proporcionen información falsa, compartan credenciales de forma que vulnere los límites del plan contratado, o incumplan estos Términos.",
          ],
        },
        {
          heading: "5. Uso aceptable — Autorización de análisis",
          body: [
            "Usted declara y garantiza que únicamente analizará código fuente, aplicaciones, sistemas y activos digitales: (a) de su propiedad; o (b) sobre los cuales posee autorización expresa, escrita y vigente del titular para realizar pruebas de seguridad. El análisis de sistemas de terceros sin autorización puede constituir delito en múltiples jurisdicciones.",
            "Queda expresamente PROHIBIDO: (a) utilizar la Plataforma para atacar, vulnerar, escanear o extraer información de sistemas sin autorización; (b) eludir o intentar eludir medidas de seguridad, límites de plan, rate limiting o controles anti-abuso; (c) realizar ingeniería inversa de la Plataforma; (d) revender, sublicenciar o compartir el acceso con terceros no autorizados; (e) introducir código malicioso destinado a comprometer la Plataforma o a otros usuarios; (f) utilizar la Plataforma para desarrollar productos competidores mediante scraping o extracción sistemática; y (g) cualquier uso ilegal o contrario a la buena fe.",
            "El incumplimiento de esta sección faculta a EATHERIA a suspender o terminar la cuenta de inmediato, sin reembolso, y a cooperar con las autoridades competentes cuando así se requiera.",
          ],
        },
        {
          heading: "6. Su código y sus datos",
          body: [
            "Usted conserva todos los derechos, título e interés sobre su código fuente, repositorios, aplicaciones y datos (\"Contenido del Cliente\"). EATHERIA no reclama propiedad alguna sobre su Contenido.",
            "Usted otorga a EATHERIA una licencia limitada, no exclusiva, revocable y no transferible para procesar su Contenido exclusivamente con el fin de prestar el servicio contratado (análisis, generación de reportes y almacenamiento de hallazgos). Los hallazgos y reportes generados a partir de su Contenido le pertenecen.",
            "Usted declara que cuenta con los derechos y autorizaciones necesarias para subir su Contenido a la Plataforma, y que dicho Contenido no infringe derechos de terceros ni contiene datos cuyo tratamiento sea ilícito.",
          ],
        },
        {
          heading: "7. Planes, facturación y pagos",
          body: [
            "Los planes disponibles (Free, Individual, Pro, Pro+ y Ultra) y sus límites de uso (número de escaneos, repositorios, usuarios y funcionalidades) se publican en la Plataforma. Los pagos se procesan a través de Stripe, Inc.; al suscribirse a un plan de pago usted acepta además los términos de Stripe.",
            "Las suscripciones de pago se renuevan automáticamente al inicio de cada período de facturación salvo cancelación previa. La cancelación surte efecto al final del período en curso, sin reembolso de cantidades ya facturadas, salvo disposición legal imperativa en contrario.",
            "Los precios pueden modificarse con aviso previo de al menos treinta (30) días. Los impuestos aplicables son responsabilidad del Cliente. El impago faculta a suspender el servicio tras aviso.",
          ],
        },
        {
          heading: "8. Plan gratuito y medidas anti-abuso",
          body: [
            "El plan gratuito está sujeto a límites técnicos y de uso publicados. Para proteger la integridad del servicio aplicamos medidas anti-abuso que incluyen límites por dirección IP, por dominio de correo corporativo y por huella de dispositivo (fingerprint).",
            "La creación de múltiples cuentas gratuitas para eludir límites, el uso de correos temporales o desechables, o cualquier forma de abuso del plan gratuito faculta a EATHERIA a bloquear las cuentas involucradas de forma permanente.",
          ],
        },
        {
          heading: "9. Disponibilidad del servicio — Sin SLA",
          body: [
            "Salvo pacto escrito en contrario, la Plataforma se ofrece sobre base de mejor esfuerzo, sin garantía de disponibilidad, nivel de servicio (SLA) ni tiempo de respuesta. Podemos realizar mantenimientos programados o de emergencia que interrumpan temporalmente el servicio.",
            "EATHERIA no será responsable de interrupciones causadas por terceros proveedores (cloud, CDN, pasarelas de pago, proveedores de IA), fallos de red, fuerza mayor o causas fuera de su control razonable.",
          ],
        },
        {
          heading: "10. Propiedad intelectual de la Plataforma",
          body: [
            "La Plataforma, incluyendo su software, motores de análisis, diseño, marcas, logotipos, documentación y know-how, es propiedad exclusiva de EATHERIA o de sus licenciantes, y está protegida por leyes de propiedad intelectual. Estos Términos no le transfieren derecho alguno de propiedad intelectual.",
            "Si usted nos envía sugerencias o retroalimentación, nos otorga el derecho de usarlas sin restricción ni compensación.",
          ],
        },
        {
          heading: "11. Confidencialidad",
          body: [
            "Cada parte se compromete a proteger la información confidencial de la otra parte con el mismo cuidado con que protege la propia, y a no divulgarla a terceros salvo: (a) a sus proveedores de servicios bajo obligaciones equivalentes (p. ej. hosting, pagos, IA); (b) cuando la ley lo exija; o (c) con consentimiento de la parte titular.",
            "Su código fuente y sus hallazgos de seguridad se tratan como información confidencial. Consulte la Política de Privacidad y Seguridad para el detalle de medidas técnicas.",
          ],
        },
        {
          heading: "12. EXENCIÓN DE GARANTÍAS",
          body: [
            "EN LA MÁXIMA MEDIDA PERMITIDA POR LA LEY APLICABLE, LA PLATAFORMA SE PROPORCIONA \"TAL CUAL\" (AS IS) Y \"SEGÚN DISPONIBILIDAD\" (AS AVAILABLE), CON TODOS SUS DEFECTOS. EATHERIA RECHAZA EXPRESAMENTE TODA GARANTÍA, EXPRESA O IMPLÍCITA, INCLUYENDO, SIN LIMITACIÓN, LAS GARANTÍAS IMPLÍCITAS DE COMERCIABILIDAD, IDONEIDAD PARA UN FIN PARTICULAR, NO INFRACCIÓN, EXACTITUD, INTEGRIDAD O UTILIDAD DE LOS RESULTADOS DE LOS ANÁLISIS.",
          ],
        },
        {
          heading: "13. LIMITACIÓN DE RESPONSABILIDAD",
          body: [
            "EN LA MÁXIMA MEDIDA PERMITIDA POR LA LEY, EATHERIA, SUS DIRECTIVOS, EMPLEADOS Y PROVEEDORES NO SERÁN RESPONSABLES DE DAÑOS INDIRECTOS, INCIDENTALES, ESPECIALES, CONSECUENTES, PUNITIVOS O EJEMPLARES, INCLUYENDO LUCRO CESANTE, PÉRDIDA DE DATOS, PÉRDIDA DE REPUTACIÓN, BRECHAS DE SEGURIDAD, INTERRUPCIÓN DEL NEGOCIO O COSTES DE REMEDIACIÓN, AUNQUE SE HUBIERA ADVERTIDO DE SU POSIBILIDAD.",
            "LA RESPONSABILIDAD TOTAL ACUMULADA DE EATHERIA DERIVADA DE O RELACIONADA CON ESTOS TÉRMINOS NO EXCEDERÁ, EN TODO CASO, EL IMPORTE EFECTIVAMENTE PAGADO POR USTED A EATHERIA EN LOS DOCE (12) MESES ANTERIORES AL HECHO QUE ORIGINE LA RECLAMACIÓN, O CIEN DÓLARES ESTADOUNIDENSES (USD 100) SI NO HUBIERA REALIZADO PAGO ALGUNO.",
            "Estas limitaciones no aplican donde la ley las prohíba (p. ej. dolo o negligencia grave cuando sea imperativo).",
          ],
        },
        {
          heading: "14. Indemnización",
          body: [
            "Usted acepta indemnizar, defender y mantener indemne a EATHERIA frente a cualquier reclamación, demanda, daño, pérdida o gasto (incluyendo honorarios razonables de abogados) derivada de: (a) su incumplimiento de estos Términos; (b) el análisis de sistemas sin la autorización requerida por la Sección 5; (c) su Contenido del Cliente o la infracción de derechos de terceros; o (d) su uso indebido de la Plataforma.",
          ],
        },
        {
          heading: "15. Suspensión y terminación",
          body: [
            "Usted puede cancelar su cuenta en cualquier momento desde la configuración o escribiendo a contacto@eatheria.com. EATHERIA puede suspender o terminar su acceso, con o sin aviso, en caso de incumplimiento de estos Términos, sospecha razonable de abuso o riesgo de seguridad, o requerimiento legal.",
            "Tras la terminación, cesa su derecho de acceso. Podemos conservar registros de auditoría (incluyendo evidencia de aceptación de términos) durante los plazos legalmente requeridos o razonables para la defensa de nuestros derechos.",
          ],
        },
        {
          heading: "16. Ley aplicable y jurisdicción",
          body: [
            "Estos Términos se rigen por las leyes de México, sin perjuicio de sus normas sobre conflicto de leyes. Cualquier controversia se someterá a los tribunales competentes de la Ciudad de México, renunciando las partes a cualquier otro fuero que pudiera corresponderles, salvo que la ley del consumidor aplicable disponga imperativamente otra cosa.",
            "Antes de iniciar cualquier procedimiento, las partes intentarán resolver la controversia de buena fe durante al menos treinta (30) días mediante comunicación escrita a contacto@eatheria.com.",
          ],
        },
        {
          heading: "17. Modificaciones a estos Términos",
          body: [
            "Podemos actualizar estos Términos. Los cambios materiales se notificarán mediante aviso en la Plataforma o por correo electrónico con al menos quince (15) días de antelación a su entrada en vigor. El uso continuado de la Plataforma tras la fecha de vigencia constituye aceptación de los Términos modificados. Si no está de acuerdo, debe cancelar su cuenta antes de dicha fecha.",
          ],
        },
        {
          heading: "18. Disposiciones generales",
          body: [
            "Estos Términos, junto con la Política de Privacidad, constituyen el acuerdo completo entre las partes. Si alguna disposición resulta inválida, las demás permanecerán vigentes. La falta de ejercicio de un derecho no constituye renuncia. Usted no puede ceder este contrato sin nuestro consentimiento escrito; nosotros podemos cederlo en el contexto de una fusión, adquisición o venta de activos. Ninguna parte será responsable por incumplimientos causados por fuerza mayor.",
            "En caso de discrepancia entre la versión en español y la versión en inglés de estos Términos, prevalecerá la versión en español.",
          ],
        },
        {
          heading: "19. Contacto",
          body: [
            "EATHERIA Security — Correo electrónico: contacto@eatheria.com — Sitio web: https://eatheria.com",
          ],
        },
      ],
    },
    en: {
      title: "Terms and Conditions of Service",
      updated: "Last updated: August 3, 2026",
      intro:
        "These Terms and Conditions of Service (the \"Terms\") constitute a legally binding agreement between you (the \"Customer\", \"you\" or the \"User\") and EATHERIA Security (\"EATHERIA\", \"we\" or the \"Company\"), operator of the platform available at eatheria.com (the \"Platform\"). BY CREATING AN ACCOUNT, CHECKING THE ACCEPTANCE BOX OR USING THE PLATFORM, YOU REPRESENT THAT YOU HAVE READ, UNDERSTOOD AND AGREE TO THESE TERMS IN THEIR ENTIRETY, AS WELL AS OUR PRIVACY POLICY. IF YOU DO NOT AGREE, YOU MUST NOT REGISTER FOR OR USE THE PLATFORM.",
      sections: [
        {
          heading: "1. Acceptance and legal capacity",
          body: [
            "By registering, you represent and warrant that: (a) you are at least 18 years old; (b) you have the legal capacity to enter into binding contracts; (c) if you register on behalf of a company or organization, you have authority to bind that entity to these Terms, in which case \"you\" refers to that entity; and (d) all information provided during registration is truthful, accurate and complete.",
            "Acceptance is perfected by checking the acceptance box during registration. EATHERIA records and retains the date, time and IP address of each acceptance as contractual evidence.",
          ],
        },
        {
          heading: "2. Service description",
          body: [
            "EATHERIA is an application security platform providing static code analysis (SAST), dynamic analysis (DAST), software composition analysis (SCA), secret detection, SBOM generation and compliance reporting (OWASP, CWE, PCI DSS, NIST), with AI-assisted validation.",
            "The service is provided as software as a service (SaaS) by subscription. We reserve the right to modify, improve, suspend or discontinue features with reasonable notice, without this giving rise to any right to compensation.",
          ],
        },
        {
          heading: "3. Indicative nature of results — No security guarantee",
          body: [
            "YOU EXPRESSLY ACKNOWLEDGE AND AGREE THAT: (a) security analyses, including those validated by artificial intelligence, are decision-support tools and DO NOT constitute a guarantee, certification or assurance that the analyzed software is secure or free of vulnerabilities; (b) no automated analysis tool can detect all existing vulnerabilities; (c) false positives and false negatives may exist; and (d) the security of your systems is and remains YOUR EXCLUSIVE RESPONSIBILITY.",
            "Results, scores, benchmarks, findings, severities and recommendations issued by the Platform are merely informative and indicative. EATHERIA shall not be liable for security breaches, data loss, attacks, exploitation of vulnerabilities (detected or not) or any damage arising from decisions made based on the Platform's results.",
          ],
        },
        {
          heading: "4. Accounts, credentials and responsibility",
          body: [
            "You are responsible for maintaining the confidentiality of your access credentials, API keys and tokens, and for all activity occurring under your account. You must notify us immediately of any unauthorized use. EATHERIA shall not be liable for losses arising from unauthorized use of your credentials where you have not implemented the available security measures (such as two-factor authentication).",
            "We reserve the right to suspend or cancel accounts that provide false information, share credentials in ways that circumvent the contracted plan limits, or breach these Terms.",
          ],
        },
        {
          heading: "5. Acceptable use — Scan authorization",
          body: [
            "You represent and warrant that you will only scan source code, applications, systems and digital assets: (a) that you own; or (b) for which you hold express, written and current authorization from the owner to perform security testing. Scanning third-party systems without authorization may constitute a crime in multiple jurisdictions.",
            "The following is expressly PROHIBITED: (a) using the Platform to attack, breach, scan or extract information from systems without authorization; (b) circumventing or attempting to circumvent security measures, plan limits, rate limiting or anti-abuse controls; (c) reverse engineering the Platform; (d) reselling, sublicensing or sharing access with unauthorized third parties; (e) introducing malicious code intended to compromise the Platform or other users; (f) using the Platform to develop competing products through scraping or systematic extraction; and (g) any unlawful or bad-faith use.",
            "Breach of this section entitles EATHERIA to immediately suspend or terminate the account, without refund, and to cooperate with competent authorities where required.",
          ],
        },
        {
          heading: "6. Your code and your data",
          body: [
            "You retain all rights, title and interest in your source code, repositories, applications and data (\"Customer Content\"). EATHERIA claims no ownership over your Content.",
            "You grant EATHERIA a limited, non-exclusive, revocable and non-transferable license to process your Content solely for the purpose of providing the contracted service (analysis, report generation and findings storage). Findings and reports generated from your Content belong to you.",
            "You represent that you hold the necessary rights and authorizations to upload your Content to the Platform, and that such Content does not infringe third-party rights nor contain data whose processing is unlawful.",
          ],
        },
        {
          heading: "7. Plans, billing and payments",
          body: [
            "Available plans (Free, Individual, Pro, Pro+ and Ultra) and their usage limits (number of scans, repositories, users and features) are published on the Platform. Payments are processed by Stripe, Inc.; by subscribing to a paid plan you also accept Stripe's terms.",
            "Paid subscriptions renew automatically at the start of each billing period unless cancelled beforehand. Cancellation takes effect at the end of the current period, without refund of amounts already billed, except where mandatory law provides otherwise.",
            "Prices may be modified with at least thirty (30) days' prior notice. Applicable taxes are the Customer's responsibility. Non-payment entitles us to suspend the service after notice.",
          ],
        },
        {
          heading: "8. Free plan and anti-abuse measures",
          body: [
            "The free plan is subject to the published technical and usage limits. To protect the integrity of the service we apply anti-abuse measures including limits per IP address, per corporate email domain and per device fingerprint.",
            "Creating multiple free accounts to circumvent limits, using temporary or disposable emails, or any form of free-plan abuse entitles EATHERIA to permanently block the accounts involved.",
          ],
        },
        {
          heading: "9. Service availability — No SLA",
          body: [
            "Unless otherwise agreed in writing, the Platform is offered on a best-effort basis, without any availability guarantee, service level agreement (SLA) or response time commitment. We may perform scheduled or emergency maintenance that temporarily interrupts the service.",
            "EATHERIA shall not be liable for interruptions caused by third-party providers (cloud, CDN, payment gateways, AI providers), network failures, force majeure or causes beyond its reasonable control.",
          ],
        },
        {
          heading: "10. Platform intellectual property",
          body: [
            "The Platform, including its software, analysis engines, design, trademarks, logos, documentation and know-how, is the exclusive property of EATHERIA or its licensors and is protected by intellectual property laws. These Terms do not transfer any intellectual property rights to you.",
            "If you send us suggestions or feedback, you grant us the right to use them without restriction or compensation.",
          ],
        },
        {
          heading: "11. Confidentiality",
          body: [
            "Each party agrees to protect the other party's confidential information with the same care it protects its own, and not to disclose it to third parties except: (a) to its service providers under equivalent obligations (e.g. hosting, payments, AI); (b) where required by law; or (c) with the owning party's consent.",
            "Your source code and security findings are treated as confidential information. See the Privacy and Security Policy for details on technical measures.",
          ],
        },
        {
          heading: "12. DISCLAIMER OF WARRANTIES",
          body: [
            "TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE PLATFORM IS PROVIDED \"AS IS\" AND \"AS AVAILABLE\", WITH ALL FAULTS. EATHERIA EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND THE ACCURACY, COMPLETENESS OR USEFULNESS OF ANALYSIS RESULTS.",
          ],
        },
        {
          heading: "13. LIMITATION OF LIABILITY",
          body: [
            "TO THE MAXIMUM EXTENT PERMITTED BY LAW, EATHERIA, ITS OFFICERS, EMPLOYEES AND PROVIDERS SHALL NOT BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, PUNITIVE OR EXEMPLARY DAMAGES, INCLUDING LOST PROFITS, LOSS OF DATA, LOSS OF REPUTATION, SECURITY BREACHES, BUSINESS INTERRUPTION OR REMEDIATION COSTS, EVEN IF ADVISED OF THEIR POSSIBILITY.",
            "EATHERIA'S TOTAL AGGREGATE LIABILITY ARISING FROM OR RELATED TO THESE TERMS SHALL NOT EXCEED, IN ANY CASE, THE AMOUNTS ACTUALLY PAID BY YOU TO EATHERIA IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO THE CLAIM, OR ONE HUNDRED U.S. DOLLARS (USD 100) IF NO PAYMENT HAS BEEN MADE.",
            "These limitations do not apply where prohibited by law (e.g. willful misconduct or gross negligence where mandatory).",
          ],
        },
        {
          heading: "14. Indemnification",
          body: [
            "You agree to indemnify, defend and hold harmless EATHERIA from any claim, demand, damage, loss or expense (including reasonable attorneys' fees) arising from: (a) your breach of these Terms; (b) scanning systems without the authorization required by Section 5; (c) your Customer Content or infringement of third-party rights; or (d) your misuse of the Platform.",
          ],
        },
        {
          heading: "15. Suspension and termination",
          body: [
            "You may cancel your account at any time from the settings or by writing to contacto@eatheria.com. EATHERIA may suspend or terminate your access, with or without notice, in case of breach of these Terms, reasonable suspicion of abuse or security risk, or legal requirement.",
            "Upon termination, your right of access ceases. We may retain audit records (including evidence of terms acceptance) for the periods legally required or reasonably necessary to defend our rights.",
          ],
        },
        {
          heading: "16. Governing law and jurisdiction",
          body: [
            "These Terms are governed by the laws of Mexico, without regard to conflict-of-law rules. Any dispute shall be submitted to the competent courts of Mexico City, the parties waiving any other jurisdiction that may correspond to them, except where applicable consumer law imperatively provides otherwise.",
            "Before initiating any proceeding, the parties will attempt to resolve the dispute in good faith for at least thirty (30) days through written communication to contacto@eatheria.com.",
          ],
        },
        {
          heading: "17. Changes to these Terms",
          body: [
            "We may update these Terms. Material changes will be notified via a notice on the Platform or by email at least fifteen (15) days before they take effect. Continued use of the Platform after the effective date constitutes acceptance of the modified Terms. If you do not agree, you must cancel your account before that date.",
          ],
        },
        {
          heading: "18. General provisions",
          body: [
            "These Terms, together with the Privacy Policy, constitute the entire agreement between the parties. If any provision is held invalid, the remainder stays in force. Failure to exercise a right does not constitute a waiver. You may not assign this contract without our written consent; we may assign it in the context of a merger, acquisition or asset sale. Neither party is liable for failures caused by force majeure.",
            "In case of discrepancy between the Spanish and English versions of these Terms, the Spanish version shall prevail.",
          ],
        },
        {
          heading: "19. Contact",
          body: [
            "EATHERIA Security — Email: contacto@eatheria.com — Website: https://eatheria.com",
          ],
        },
      ],
    },
  },
  privacy: {
    es: {
      title: "Política de Privacidad",
      updated: "Última actualización: 3 de agosto de 2026",
      intro:
        "Esta Política de Privacidad describe cómo EATHERIA Security (\"EATHERIA\", \"nosotros\") recopila, utiliza, almacena, comparte y protege la información personal y los datos procesados a través de la plataforma eatheria.com (la \"Plataforma\"). Al registrarse y aceptar los Términos de Servicio, usted reconoce haber leído esta Política.",
      sections: [
        {
          heading: "1. Responsable del tratamiento",
          body: [
            "El responsable del tratamiento de sus datos es EATHERIA Security, contactable en contacto@eatheria.com. Para usuarios del Espacio Económico Europeo o el Reino Unido, actuamos como responsable del tratamiento de los datos de su cuenta y como encargado del tratamiento del código y datos que usted sube para análisis.",
          ],
        },
        {
          heading: "2. Datos que recopilamos",
          body: [
            "Datos de cuenta: nombre, apellidos, correo electrónico, nombre de empresa, plan contratado, idioma preferido y credenciales de autenticación (almacenadas mediante verificadores SRP: nunca almacenamos su contraseña en texto claro ni un hash reversible de la misma).",
            "Datos de facturación: procesados directamente por Stripe, Inc. EATHERIA no almacena números completos de tarjeta; únicamente identificadores de cliente/suscripción de Stripe, plan y estado de pago.",
            "Datos técnicos y de auditoría: dirección IP, agente de usuario, huella de dispositivo (fingerprint) para prevención de abuso, registros de inicio de sesión (fecha, IP), fecha e IP de aceptación de los Términos, y registros de auditoría de acciones dentro de la Plataforma.",
            "Contenido del Cliente: código fuente, repositorios, configuraciones y archivos que usted sube o conecta para análisis, así como los hallazgos, reportes y metadatos derivados (que pueden incluir fragmentos de código relevantes para documentar cada vulnerabilidad).",
            "Comunicaciones: mensajes enviados mediante formularios de contacto o correo electrónico.",
          ],
        },
        {
          heading: "3. Finalidades y bases jurídicas",
          body: [
            "Utilizamos sus datos para: (a) prestar el servicio contratado (ejecución de contrato); (b) autenticación y seguridad de la cuenta (interés legítimo y obligación de seguridad); (c) prevención de abuso y fraude (interés legítimo); (d) facturación y obligaciones fiscales (obligación legal); (e) comunicaciones transaccionales del servicio; (f) mejora de la Plataforma mediante estadísticas agregadas y anonimizadas (interés legítimo); y (g) cumplimiento de obligaciones legales y defensa de derechos (evidencia de aceptación de términos, registros de auditoría).",
            "No vendemos sus datos personales. No utilizamos su código fuente para entrenar modelos de inteligencia artificial.",
          ],
        },
        {
          heading: "4. Procesamiento de su código fuente",
          body: [
            "El código que usted envía se procesa exclusivamente para ejecutar los análisis solicitados y generar sus reportes. Los hallazgos almacenados pueden incluir fragmentos de código estrictamente necesarios para documentar cada vulnerabilidad (archivo, línea y contexto).",
            "Para la validación asistida por IA, fragmentos relevantes de código pueden ser enviados al proveedor de IA configurado (por defecto Google Gemini, bajo sus términos de procesamiento de datos). Usted puede configurar su propio proveedor/clave de IA en la configuración de su empresa.",
            "Usted puede eliminar sus proyectos y reportes desde la Plataforma; la eliminación se aplica también a los fragmentos asociados, sin perjuicio de las copias de seguridad durante su ciclo de vida.",
          ],
        },
        {
          heading: "5. Subencargados y terceros proveedores",
          body: [
            "Compartimos datos con los siguientes proveedores, en la medida estrictamente necesaria: Stripe, Inc. (pagos, EE. UU.); DigitalOcean (infraestructura de hosting); Cloudflare, Inc. (CDN, protección DDoS, verificación anti-bot Turnstile); Google LLC (Gemini, validación de hallazgos por IA); y FormSubmit.co (entrega de notificaciones por correo del formulario de contacto).",
            "Cada proveedor trata los datos conforme a sus propias políticas y, cuando aplica, bajo cláusulas contractuales tipo u mecanismos equivalentes de transferencia internacional de datos.",
          ],
        },
        {
          heading: "6. Cookies y almacenamiento local",
          body: [
            "Utilizamos cookies estrictamente necesarias para el funcionamiento del servicio: cookie de sesión de autenticación, preferencia de idioma (aetheria-locale) y tokens anti-CSRF. No utilizamos cookies publicitarias ni de seguimiento de terceros con fines de marketing.",
            "Cloudflare Turnstile puede establecer cookies técnicas propias para la verificación anti-bot en los formularios públicos.",
          ],
        },
        {
          heading: "7. Conservación de datos",
          body: [
            "Conservamos los datos de su cuenta mientras esta permanezca activa. Tras la cancelación o eliminación, los datos personales se eliminan o anonimizan en un plazo razonable, salvo: (a) registros de auditoría y evidencia contractual (aceptación de términos, registros de seguridad), que pueden conservarse hasta 5 años por obligaciones legales y defensa de derechos; y (b) copias de seguridad, que se depuran según su ciclo de rotación.",
          ],
        },
        {
          heading: "8. Transferencias internacionales",
          body: [
            "Sus datos pueden ser procesados en servidores ubicados fuera de su país de residencia (incluyendo Estados Unidos y la Unión Europea) por efecto de nuestra infraestructura y la de nuestros proveedores. Adoptamos las salvaguardas contractualmente requeridas para dichas transferencias cuando la ley aplicable lo exige.",
          ],
        },
        {
          heading: "9. Sus derechos",
          body: [
            "Conforme a la legislación aplicable (incluyendo GDPR, LFPDPPP de México y, en su caso, CCPA/CPRA), usted puede ejercer los derechos de acceso, rectificación, cancelación/eliminación, oposición, limitación del tratamiento, portabilidad y revocación del consentimiento, escribiendo a contacto@eatheria.com. Responderemos dentro de los plazos legalmente exigidos.",
            "Usted tiene derecho a presentar una reclamación ante la autoridad de protección de datos de su jurisdicción. Si se encuentra en California, tiene derecho a solicitar detalles sobre las categorías de datos recopilados y a no ser discriminado por ejercer sus derechos; no vendemos ni compartimos datos personales para publicidad conductual.",
          ],
        },
        {
          heading: "10. Medidas de seguridad",
          body: [
            "Aplicamos medidas técnicas y organizativas que incluyen: cifrado en tránsito (TLS), cifrado de claves API de clientes con AES-256-GCM, autenticación de conocimiento cero (SRP) sin almacenamiento de contraseñas, autenticación de dos factores opcional, control de acceso basado en roles, aislamiento de datos por empresa, registros de auditoría, limitación de tasa y protección anti-bot.",
            "Ningún sistema es infalible; en caso de incidente de seguridad que afecte a sus datos personales, le notificaremos conforme a los plazos y condiciones de la legislación aplicable.",
          ],
        },
        {
          heading: "11. Menores de edad",
          body: [
            "La Plataforma está dirigida a profesionales y empresas y no está destinada a menores de 18 años. No recopilamos deliberadamente datos de menores. Si detectamos datos de un menor, los eliminaremos.",
          ],
        },
        {
          heading: "12. Cambios a esta Política",
          body: [
            "Podemos actualizar esta Política. Los cambios materiales se notificarán mediante aviso en la Plataforma o por correo electrónico antes de su entrada en vigor, indicando la fecha de última actualización al inicio del documento.",
          ],
        },
        {
          heading: "13. Contacto",
          body: [
            "Para cualquier consulta sobre privacidad o para ejercer sus derechos: contacto@eatheria.com",
          ],
        },
      ],
    },
    en: {
      title: "Privacy Policy",
      updated: "Last updated: August 3, 2026",
      intro:
        "This Privacy Policy describes how EATHERIA Security (\"EATHERIA\", \"we\") collects, uses, stores, shares and protects personal information and data processed through the eatheria.com platform (the \"Platform\"). By registering and accepting the Terms of Service, you acknowledge that you have read this Policy.",
      sections: [
        {
          heading: "1. Data controller",
          body: [
            "The controller of your data is EATHERIA Security, reachable at contacto@eatheria.com. For users in the European Economic Area or the United Kingdom, we act as controller of your account data and as processor of the code and data you upload for analysis.",
          ],
        },
        {
          heading: "2. Data we collect",
          body: [
            "Account data: first name, last name, email address, company name, contracted plan, preferred language, and authentication credentials (stored via SRP verifiers: we never store your password in plain text nor a reversible hash of it).",
            "Billing data: processed directly by Stripe, Inc. EATHERIA does not store full card numbers; only Stripe customer/subscription identifiers, plan and payment status.",
            "Technical and audit data: IP address, user agent, device fingerprint for abuse prevention, login records (date, IP), date and IP of Terms acceptance, and audit logs of actions within the Platform.",
            "Customer Content: source code, repositories, configurations and files you upload or connect for analysis, as well as the resulting findings, reports and metadata (which may include code snippets relevant to documenting each vulnerability).",
            "Communications: messages sent via contact forms or email.",
          ],
        },
        {
          heading: "3. Purposes and legal bases",
          body: [
            "We use your data to: (a) provide the contracted service (performance of a contract); (b) account authentication and security (legitimate interest and security obligation); (c) abuse and fraud prevention (legitimate interest); (d) billing and tax obligations (legal obligation); (e) transactional service communications; (f) Platform improvement through aggregated, anonymized statistics (legitimate interest); and (g) compliance with legal obligations and defense of rights (evidence of terms acceptance, audit logs).",
            "We do not sell your personal data. We do not use your source code to train artificial intelligence models.",
          ],
        },
        {
          heading: "4. Processing of your source code",
          body: [
            "The code you submit is processed exclusively to run the requested analyses and generate your reports. Stored findings may include code snippets strictly necessary to document each vulnerability (file, line and context).",
            "For AI-assisted validation, relevant code snippets may be sent to the configured AI provider (by default Google Gemini, under its data processing terms). You may configure your own AI provider/key in your company settings.",
            "You can delete your projects and reports from the Platform; deletion also applies to associated snippets, without prejudice to backups during their lifecycle.",
          ],
        },
        {
          heading: "5. Sub-processors and third-party providers",
          body: [
            "We share data with the following providers, to the extent strictly necessary: Stripe, Inc. (payments, USA); DigitalOcean (hosting infrastructure); Cloudflare, Inc. (CDN, DDoS protection, Turnstile anti-bot verification); Google LLC (Gemini, AI findings validation); and FormSubmit.co (delivery of contact-form email notifications).",
            "Each provider processes data under its own policies and, where applicable, under standard contractual clauses or equivalent international data transfer mechanisms.",
          ],
        },
        {
          heading: "6. Cookies and local storage",
          body: [
            "We use strictly necessary cookies for the operation of the service: authentication session cookie, language preference (aetheria-locale) and anti-CSRF tokens. We do not use advertising or third-party tracking cookies for marketing purposes.",
            "Cloudflare Turnstile may set its own technical cookies for anti-bot verification on public forms.",
          ],
        },
        {
          heading: "7. Data retention",
          body: [
            "We retain your account data while the account remains active. After cancellation or deletion, personal data is deleted or anonymized within a reasonable period, except: (a) audit records and contractual evidence (terms acceptance, security logs), which may be retained for up to 5 years for legal obligations and defense of rights; and (b) backups, which are purged according to their rotation cycle.",
          ],
        },
        {
          heading: "8. International transfers",
          body: [
            "Your data may be processed on servers located outside your country of residence (including the United States and the European Union) due to our infrastructure and that of our providers. We adopt the contractually required safeguards for such transfers where applicable law demands them.",
          ],
        },
        {
          heading: "9. Your rights",
          body: [
            "Under applicable law (including GDPR, Mexico's LFPDPPP and, where applicable, CCPA/CPRA), you may exercise the rights of access, rectification, cancellation/deletion, objection, restriction of processing, portability and withdrawal of consent, by writing to contacto@eatheria.com. We will respond within the legally required timeframes.",
            "You have the right to lodge a complaint with the data protection authority of your jurisdiction. If you are in California, you have the right to request details about the categories of data collected and not to be discriminated against for exercising your rights; we do not sell or share personal data for behavioral advertising.",
          ],
        },
        {
          heading: "10. Security measures",
          body: [
            "We apply technical and organizational measures including: encryption in transit (TLS), AES-256-GCM encryption of customer API keys, zero-knowledge authentication (SRP) with no password storage, optional two-factor authentication, role-based access control, per-company data isolation, audit logging, rate limiting and anti-bot protection.",
            "No system is infallible; in the event of a security incident affecting your personal data, we will notify you in accordance with the timeframes and conditions of applicable law.",
          ],
        },
        {
          heading: "11. Minors",
          body: [
            "The Platform is intended for professionals and businesses and is not directed at persons under 18. We do not knowingly collect data from minors. If we detect data from a minor, we will delete it.",
          ],
        },
        {
          heading: "12. Changes to this Policy",
          body: [
            "We may update this Policy. Material changes will be notified via a notice on the Platform or by email before they take effect, with the last-updated date shown at the top of the document.",
          ],
        },
        {
          heading: "13. Contact",
          body: [
            "For any privacy inquiry or to exercise your rights: contacto@eatheria.com",
          ],
        },
      ],
    },
  },
  security: {
    es: {
      title: "Seguridad y Divulgación Responsable",
      updated: "Última actualización: 3 de agosto de 2026",
      intro:
        "La seguridad es el núcleo de nuestro producto. Esta página describe las medidas con las que protegemos la Plataforma y sus datos, y nuestro programa de divulgación responsable de vulnerabilidades.",
      sections: [
        {
          heading: "1. Medidas de seguridad de la Plataforma",
          body: [
            "Autenticación de conocimiento cero (SRP): su contraseña nunca abandona su navegador y jamás se almacena, ni siquiera como hash convencional. Opción de autenticación de dos factores (2FA) con códigos de respaldo.",
            "Cifrado: TLS en todo el tráfico; las claves API que usted registra en la Plataforma se cifran con AES-256-GCM antes de persistirse. Bloqueo de cuenta tras intentos fallidos de inicio de sesión y limitación de tasa en endpoints sensibles.",
            "Aislamiento: todos los datos se segregan por empresa (multi-tenancy con control estricto por companyId). Control de acceso basado en roles (RBAC) con permisos granulares y registro de auditoría de las operaciones sensibles.",
            "Infraestructura: protección DDoS y WAF de Cloudflare, verificación anti-bot Turnstile en formularios públicos, y políticas de seguridad de contenido (CSP) restrictivas.",
          ],
        },
        {
          heading: "2. Practicamos lo que vendemos",
          body: [
            "EATHERIA se analiza a sí misma de forma continua con su propio motor. Publicamos nuestros resultados de benchmarks y postura de seguridad (incluyendo OpenSSF Scorecard 10/10) en eatheria.com/benchmarks, junto con la evidencia descargable.",
          ],
        },
        {
          heading: "3. Programa de divulgación responsable",
          body: [
            "Si usted es un investigador de seguridad y cree haber encontrado una vulnerabilidad en eatheria.com o en la Plataforma, le agradecemos que nos la comunique de forma responsable a contacto@eatheria.com con el asunto \"Security Report\", incluyendo descripción, pasos de reproducción e impacto potencial.",
            "Compromisos: (a) acusaremos recibo en un plazo máximo de 72 horas; (b) le mantendremos informado del estado de la remediación; (c) no emprenderemos acciones legales contra investigaciones de buena fe que respeten estas reglas; y (d) con su consentimiento, reconoceremos públicamente su hallazgo una vez corregido.",
            "Reglas de la casa (safe harbor): no acceda, modifique ni exfiltre datos de otros usuarios; no degrade ni interrumpa el servicio (no DoS); no realice ingeniería social contra nuestro equipo ni clientes; utilice cuentas de prueba propias; y no divulgue públicamente la vulnerabilidad antes de que sea corregida o transcurran 90 días.",
            "Fuera de alcance: vulnerabilidades en servicios de terceros (Stripe, Cloudflare), reportes puramente teóricos sin impacto demostrable, auto-XSS, y hallazgos que requieran acceso físico o ingeniería social.",
          ],
        },
        {
          heading: "4. Respuesta a incidentes",
          body: [
            "En caso de incidente de seguridad que afecte a datos personales o de clientes, notificaremos a los afectados y a las autoridades conforme a los plazos de la legislación aplicable, junto con las medidas de mitigación adoptadas.",
          ],
        },
        {
          heading: "5. Reporte",
          body: [
            "Canal de contacto de seguridad: contacto@eatheria.com (asunto: \"Security Report\"). Por favor, no abra issues públicos ni publique detalles antes de la remediación.",
          ],
        },
      ],
    },
    en: {
      title: "Security & Responsible Disclosure",
      updated: "Last updated: August 3, 2026",
      intro:
        "Security is the core of our product. This page describes the measures with which we protect the Platform and your data, and our responsible vulnerability disclosure program.",
      sections: [
        {
          heading: "1. Platform security measures",
          body: [
            "Zero-knowledge authentication (SRP): your password never leaves your browser and is never stored, not even as a conventional hash. Optional two-factor authentication (2FA) with backup codes.",
            "Encryption: TLS on all traffic; API keys you register on the Platform are encrypted with AES-256-GCM before persistence. Account lockout after failed login attempts and rate limiting on sensitive endpoints.",
            "Isolation: all data is segregated per company (multi-tenancy with strict companyId scoping). Role-based access control (RBAC) with granular permissions and audit logging of sensitive operations.",
            "Infrastructure: Cloudflare DDoS protection and WAF, Turnstile anti-bot verification on public forms, and restrictive Content Security Policies (CSP).",
          ],
        },
        {
          heading: "2. We practice what we sell",
          body: [
            "EATHERIA continuously scans itself with its own engine. We publish our benchmark results and security posture (including OpenSSF Scorecard 10/10) at eatheria.com/benchmarks, along with downloadable evidence.",
          ],
        },
        {
          heading: "3. Responsible disclosure program",
          body: [
            "If you are a security researcher and believe you have found a vulnerability in eatheria.com or the Platform, we ask you to report it responsibly to contacto@eatheria.com with the subject \"Security Report\", including description, reproduction steps and potential impact.",
            "Our commitments: (a) we will acknowledge receipt within a maximum of 72 hours; (b) we will keep you informed of remediation status; (c) we will not take legal action against good-faith research that respects these rules; and (d) with your consent, we will publicly acknowledge your finding once fixed.",
            "House rules (safe harbor): do not access, modify or exfiltrate other users' data; do not degrade or disrupt the service (no DoS); do not perform social engineering against our team or customers; use your own test accounts; and do not publicly disclose the vulnerability before it is fixed or 90 days have elapsed.",
            "Out of scope: vulnerabilities in third-party services (Stripe, Cloudflare), purely theoretical reports without demonstrable impact, self-XSS, and findings requiring physical access or social engineering.",
          ],
        },
        {
          heading: "4. Incident response",
          body: [
            "In the event of a security incident affecting personal or customer data, we will notify affected parties and authorities in accordance with the timeframes of applicable law, together with the mitigation measures adopted.",
          ],
        },
        {
          heading: "5. Reporting",
          body: [
            "Security contact channel: contacto@eatheria.com (subject: \"Security Report\"). Please do not open public issues or publish details before remediation.",
          ],
        },
      ],
    },
  },
};
