#!C:\Users\Andyr\AppData\Local\Programs\Python\Python311\python.exe
print("Content-Type: text/html\n")

import mysql.connector
from flask import Flask, request, redirect, render_template, url_for, session
import os
app = Flask(__name__)
app.secret_key = os.urandom(24)

conn = mysql.connector.connect(
        host="localhost", 
        port="3306", 
        user="root", 
        password="", 
        database="assessment_results"
    )
cursor = conn.cursor()

@app.route('/')
def index():
    #render_template('Website.html')
    return render_template('Website.html') 

@app.route("/submit", methods=["POST"])
def submit():
    form_data = request.form
    required_fields = ['company_name', 'industry', 'employee_count', 'num_security_employees', 'securityBreach',
       'passwordRequirements', 'accessRemoval', 'multifactorCredentials', 'logicalAccess', 'disasterRecoveryPlan',
       'incidentResponseTeam', 'incidentResponsePlanTesting', 'securityTools', 'cyberInsurance', 'dataBackups',
       'dataRemoval', 'externalDevices', 'cybersecurityArchitecture', 'assetInventory', 'networkProtection',
       'confidentialDataEncryption', 'leastFunctionality', 'securityApplications', 'vulnerability_assessments',
       'cyber_risk_management', 'risk_management_program', 'risk_mitigation_strategies', 'vendor_management',
       'humanResourcePolicy', 'secureCoding', 'securityAwareness', 'backgroundChecks', 'cybersecurityResponsibilities',
       'thirdPartyAssessment', 'physicalAccessControls', 'changeManagementProcess',
       'documentedSecurityPolicies', 'policiesReviewed', 'physicalAccessRevoked', 'gdprCompliant']
    for field in required_fields:
        if field not in form_data:
            session['form_data'] = form_data
            return '<script>alert("Error: You have not answered all questions, please go back and answer all of the questions"); history.back();</script>'.format(field)
        if not form_data[field]:
            session['form_data'] = form_data
            return '<script>alert("Error: You have not answered all questions, please go back and answer all of the questions"); history.back();</script>'.format(field)

    query = """
        INSERT INTO survey_data (
            company_name, industry, employee_count, num_security_employees, securityBreach, 
            password_Requirements, accessRemoval, multifactorCredentials, logicalAccess, disasterRecoveryPlan, 
            incidentResponseTeam, incidentResponsePlanTesting, securityTools, cyberInsurance, dataBackups, 
            dataRemoval, externalDevices, cybersecurityArchitecture, assetInventory, networkProtection, 
            confidentialDataEncryption, leastFunctionality, securityApplications, vulnerability_assessments, 
            cyber_risk_management, risk_management_program, risk_mitigation_strategies, vendor_management, 
            humanResourcePolicy, secureCoding, securityAwareness, backgroundChecks, cybersecurityResponsibilities, 
            thirdPartyAssessment, physicalAccessControls, changeManagementProcess, 
            documentedSecurityPolicies, policiesReviewed, physicalAccessRevoked, gdprCompliant
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    
    values = tuple(form_data.values())
    
    cursor.execute(query, values)
    conn.commit()

    return redirect(url_for('results', id = cursor.lastrowid))


@app.route('/results', methods=['GET'])
def results():
    # Define the SQL query to retrieve the answers from the survey results
    query = "SELECT * FROM survey_data WHERE id = %s"

    # Execute the query
    cursor.execute(query, (request.args.get('id'),))

    # Initialise the answers dictionary
    answers = {}

    # Retrieve all survey data for the selected company from the database
    results = cursor.fetchall()

    # Assign the company name to a variable
    company_name = results[0][1]

    # Iterate through the rows and add the answers to the dictionary
    for row in results:
        for i in range(len(row)):
            column_name = cursor.column_names[i]
            answer = row[i]
            answers[column_name] = answer
            
    # Define the risk score variable
    risk_score = 0
     # Define the questions and corresponding points
     #Comments relate each security question to the correspoding control in the Secure Controls Framework
    questions = {
        "industry":0,
        "securityBreach": 8,      #IRO-04.1
        "password_Requirements":0,
        "accessRemoval": 10,        #IAC-07.2
        "multifactorCredentials": 9,    #IAC-06
        "logicalAccess": 10,        #IAC-20
        "disasterRecoveryPlan": 10, #BCD-01
        "incidentResponseTeam": 8,  #OPS-04
        "incidentResponsePlanTesting": 9,   #IRO-06 + IRO-07
        "securityTools": 9,     #NET-08
        "cyberInsurance": 10,   
        "dataBackups": 10,   #BCD-11
        "dataRemoval": 10,      #AST-09
        "externalDevices": 7,   #NET-05.2
        "cybersecurityArchitecture": 9,     #AST-06
        "assetInventory": 10,          #AST-02
        "networkProtection": 9, #MON-01.1
        "confidentialDataEncryption": 10,   #CRY-03 + CRY-05
        "leastFunctionality": 10,        #CFG-03
        "securityApplications": 10,      #END-01
        "vulnerability_assessments": 7,  #TDA-06.2
        "cyber_risk_management": 10,     #RSK-01
        "risk_management_program": 10,   #RSK-06 + RSK-04
        "risk_mitigation_strategies": 9, #RSK-06.2
        "vendor_management": 10,          #RSK-09
        "humanResourcePolicy": 10,        #HRS=05
        "secureCoding": 10,     #TDA-06
        "securityAwareness": 9, #SAT-04
        "backgroundChecks": 10, #HRS-04
        "cybersecurityResponsibilities": 10,    #HRS-03
        "thirdPartyAssessment": 0,
        "physicalAccessControls": 10,       #PES-04 + PES-03
        "changeManagementProcess": 10,      #CHG-01
        "documentedSecurityPolicies": 10,   #HRS-05
        "policiesReviewed": 10,             #GOV-03
        "physicalAccessRevoked": 9,         #IAC-20.6
        "gdprCompliant": 10                 #PRI-01
        }
       #Multiple choice questions
    password_requirements = {
        "no": 9,            #IAC-10.1
        "uppercase": 5,     #IAC-10.1
        "numeric": 5,       #IAC-10.1
        "special": 5,       #IAC-10.1
        "min-8": 5,         #IAC-10.1
        "all": 0            #IAC-10.1
            }
    third_party_assessment = {
        "no": 9,      #TPM-02 + TPM-03 + RSK-09.1 + TPM-08
        "onboarding": 9,    #TPM-08
        "12": 0,      #TPM-02 + TPM-03 + RSK-09.1 + TPM-08
        "2": 0,       #TPM-02 + TPM-03 + RSK-09.1 + TPM-08
        "2+": 5,      #TPM-08
        "breach": 9   #TPM-08
            }

    # Iterate through the answers and add the corresponding weights to the risk score 
    for question, answer in answers.items():
        if question == "securityBreach" and answer == "yes":
            risk_score += questions[question]
        elif answer == "no" and question != "securityBreach":
            risk_score += questions[question]
        elif question == "password_Requirements":
            risk_score += password_requirements[answer]
        elif question == "thirdPartyAssessment":
            risk_score += third_party_assessment[answer]
    
            
    # Calculate the percentage risk score
    total_possible_risk_score = sum(questions.values()) + sum(password_requirements.values()) + sum(third_party_assessment.values())
    percentage_risk_score = risk_score / total_possible_risk_score
    percentage_risk_score = risk_score / total_possible_risk_score * 100
    percentage_risk_score = int(percentage_risk_score)
   
    # Check the percentage risk score and set the output message
    if percentage_risk_score == 0:
        output_message = "Congratulations! Your company has a perfect security score. Keep up the good work and continue to review and improve your security measures."
    elif percentage_risk_score <= 25:
        output_message = "Congratulations! your score is low! Your company is at an adequate level of security, please see the below reccomendations for how you can improve this score further!"
    elif percentage_risk_score <= 50:
        output_message = "Your score is medium, this means you have a fair amount of securty measures in your company. However there is still improvements that can be made to reduce your security risk!"
    elif percentage_risk_score <= 70:
        output_message = "Your score is High, be warned that your organisation does not have a sufficient level of security measures in place. Please implement the below reccomendations to reduce the risks to your company."
    else:
        output_message = "WARNING: This score is critically High, It is urgent that you seek assistance to implement the security reccomendations below!"

    # Initialise the recommendations variable
    recommendations = []  
    
    id = request.args.get('id')

    # Execute the query
    cursor.execute(query, (id,))

   # Retrieve all survey data for the selected company from the database
    for row in cursor.fetchall():
    # Iterate through the row and add the answers to the dictionary
        for i in range(len(row)):
            column_name = cursor.column_names[i]
            answer = row[i]
            answers[column_name] = answer
    # Reccomended improvements for the company based on their answers
        # Recommendations for industry relevant regulations
        industry = answers["industry"]
        industry_reccomendations = {
        "financial_services": "As you are in the financial services industry, we recommend that you review regulations such as the Payment Card Industry Data Security Standard (PCI DSS) and the General Data Protection Regulation (GDPR).",
        "technology": "As you are in the technology industry, we recommend that you review regulations such as the Health Insurance Portability and Accountability Act (HIPAA) and the Federal Risk and Authorisation Management Program (FedRAMP).",
        "healthcare": "As you are in the healthcare industry, we recommend that you review regulations such as the Health Insurance Portability and Accountability Act (HIPAA) and the General Data Protection Regulation (GDPR).",
        "manufacturing": "As you are in the manufacturing industry, we recommend that you review regulations such as the Occupational Safety and Health Administration (OSHA) and the Environmental Protection Agency (EPA).",
        "retail": "As you are in the retail industry, we recommend that you review regulations such as the Payment Card Industry Data Security Standard (PCI DSS) and the Fair Credit Reporting Act (FCRA).",
        "government": "As you are in the government industry, we recommend that you review regulations such as the Federal Risk and Authorisation Management Program (FedRAMP) and the Federal Information Security Modernisation Act (FISMA).",
        "education": "As you are in the education industry, we recommend that you review regulations such as the Family Educational Rights and Privacy Act (FERPA) and the Children's Online Privacy Protection Act (COPPA).",
        "transportation": "As you are in the transportation industry, we recommend that you review regulations such as the Department of Transportation (DOT) and the International Air Transport Association (IATA).",
        "energy": "As you are in the energy industry, we recommend that you review regulations such as the North American Electric Reliability Corporation (NERC) and the Occupational Safety and Health Administration (OSHA).",
        "other": "Please refer to your local jurisdiction regulations and standards for further guidence on improving your security."
        }
        recommendations.append(industry_reccomendations[industry])
        # Recommendations for employee count and security team size
        if answers["employee_count"] == "1-50" and answers["num_security_employees"] == "0":
            recommendations.append("We recomend that companies with 1-50 employees have at least one person dedicated to security. As your company does not have any security personnel, we recommend that you consider adding at least one person to your team or assigning this responsibility to an existing employee that can implement some of the reccomendations below.")
        elif answers["employee_count"] == "51-250" and answers["num_security_employees"] in ["0", "1-3"]:
            recommendations.append("We recommend that companies with 51-250 employees have at least 4-6 security personnel. As your company has fewer than 4-6 security personnel, we recommend that you consider increasing the size of your security team to ensure that you are properly staffed in order to protect against cyber threats. This includes regular security assessments and audits, implementing robust incident response plans and regularly reviewing and updating security policies and procedures.")
        elif answers["employee_count"] == "251-500" and answers["num_security_employees"] in ["0", "1-3", "4-6"]:
            recommendations.append("We recommend that companies with 251-500 employees have at least 7-10 security personnel. As your company has fewer than 7-10 security personnel, we recommend that you consider increasing the size of your security team to ensure that you are properly staffed in order to protect against cyber threats. This includes regular security assessments and audits, implementing robust incident response plans and regularly reviewing and updating security policies and procedures.")
        elif answers["employee_count"] == "501-1000" and answers["num_security_employees"] in ["0", "1-3", "4-6", "7-10"]:
            recommendations.append("We recommend that companies with 501-1000 employees have at least 10-15 security personnel. As your company has fewer than 10-15 security personnel, we recommend that you consider increasing the size of your security team to ensure that you are properly staffed in order to protect against cyber threats. This includes regular security assessments and audits, implementing robust incident response plans and regularly reviewing and updating security policies and procedures.")
        elif answers["employee_count"] == "1000+" and answers["num_security_employees"] in ["0", "1-3", "4-6", "7-10", "10-15"]:
            recommendations.append("We recommend that companies with 1000+ employees have at least 20 security personnel. As your company has fewer than 20 security personnel, we recommend that you consider increasing the size of your security team to ensure that you are properly staffed in order to protect against cyber threats. This includes regular security assessments and audits, implementing robust incident response plans and regularly reviewing and updating security policies and procedures.")
    
        # Recommendations for "Has your company suffered a Security breach in the last 12 months?"
        if answers["securityBreach"] == "yes":
            recommendations.append(" As your company has suffered a security breach, it's important to carefully review what happened and how it occurred. One helpful resource for this process is the ICO (Information Commissioner's Office) Accountability Framework. This framework provides guidance on how to respond to and monitor breaches. <a href=https://ico.org.uk/for-organisations/accountability-framework/breach-response-and-monitoring/#incidents'>ICO's guidance</a>. Additionally, it may be useful to review any relevant industry standards or frameworks, such as the NIST Cybersecurity Framework, to identify any potential weaknesses in your current security measures and determine what steps you can take to strengthen them.")

        # Recommendations for "Does the company set password complexity requirements and require periodic changes?"
        password_Requirements = answers["password_Requirements"]
        password_Recommendations = {
        "no": "It is important to set password complexity requirements and require periodic changes in order to protect against the risk of brute force attacks and other types of password cracking. According to the (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) guidelines, password complexity should have a minimum length of 12-14 characters and be complex and different from previous passwords. We recommend setting requirements such as minimum length, upper and lowercase characters, numbers and special characters, and requiring that passwords be changed at least every 90 days.",
        "uppercase": "Requiring uppercase characters is a good start for your password complexity requirements, but it is important to also have a minimum length, lowercase characters, numbers, special characters as well as requiring periodic password changes. This will help protect against the risk of brute force attacks and other types of password cracking. Remember, (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) guidelines recommend a minimum length of 12-14 characters and be complex and different from previous passwords.",
        "numeric": "Requiring numeric characters is a good start for your password complexity requirements, but it is important to also have a minimum length, uppercase and lowercase characters, special characters as well as requiring periodic password changes. This will help protect against the risk of brute force attacks and other types of password cracking. Remember, (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) guidelines recommend a minimum length of 12-14 characters and be complex and different from previous passwords.",
        "special": "Requiring special characters is a good start for your password complexity requirements, but it is important to also have a minimum length, uppercase and lowercase characters, numbers as well as requiring periodic password changes. This will help protect against the risk of brute force attacks and other types of password cracking. Remember, (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) guidelines recommend a minimum length of 12-14 characters and be complex and different from previous passwords.",
        "min-8": "A minimum length of 8 characters is a good start for your password complexity requirements, but it is important to also have uppercase and lowercase characters, numbers, special characters as well as requiring periodic password changes. This will help protect against the risk of brute force attacks and other types of password cracking. Remember, (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) guidelines recommend a minimum length of 12-14 characters and be complex and different from previous passwords."
        }
        recommendations.append(password_Recommendations[password_Requirements])

        # Recommendations for "Is there a process to remove access to systems containing scoped data within 24 hours for terminated constituents?"
        if answers["accessRemoval"] == "no":
            recommendations.append("It is important to have a process in place to promptly remove access to systems containing scoped data for terminated constituents. This is a fundamental policy in ITIL (Information Technology Infrastructure Library) and failure to do so can leave your company vulnerable to data breaches or unauthorised access. Some suggestions for improving this process include implementing automated deactivation of access upon employee termination, regularly reviewing and auditing access permissions, and establishing clear guidelines and procedures for revoking access.")
    
        # Recommendations for "Are stronger or multifactor credentials required for access that poses higher risk to the function (such as privileged accounts, service accounts, shared accounts and remote access)?"
        if answers["multifactorCredentials"] == "no":
            recommendations.append("Implementing MultiFactor Authentication (MFA) for access that poses higher risk to the function, such as privileged accounts, service accounts, shared accounts, and remote access, is an important security measure that should be implemented by your company. MFA helps to prevent unauthorised access by requiring an additional form of authentication, such as a code sent to a phone or a security token. (<a href='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf'>NIST.SP.800-63-3. 1</a>) provides guidelines for implementing MFA, and it is also a best practice recommended by ITIL. Implementing MFA can significantly reduce the risk of security breaches and protect your company's sensitive data. For more guidance on implementing MFA, you may want to consult these resources or seek out additional guidance from industry experts.")

        # Recommendations for "Logical access requirements incorporate the principles of least privilege and separation of duties?"
        if answers["logicalAccess"] == "no":
            recommendations.append("The principle of least privilege means that users should only have the minimum level of access necessary to perform their job duties. Separation of duties means that different users or groups of users are responsible for different aspects of a task, so that no single individual has complete control. We recommend reviewing and implementing these principles in your access controls. There are various standards and frameworks that can guide you in this, such as the NIST Cybersecurity Framework and the ISO 27001 standard.")
            
        # Recommendations for "Do you have a disaster recovery and incident response plan in place?"
        if answers["disasterRecoveryPlan"] == "no":
            recommendations.append("The National Institute of Standards and Technology (NIST) Disaster Recovery Contingency Planning Guide (<a href='https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final'>NIST SP 800-34 Rev. 1</a>) provides guidelines for organisations to follow when developing and implementing a disaster recovery contingency plan. The guide covers key considerations for disaster recovery planning, including risk assessment, business impact analysis, and the development of recovery strategies. It also provides guidance on the testing and maintenance of the disaster recovery plan, as well as the roles and responsibilities of key personnel during a disaster recovery event. The guide is intended to assist organisations in developing a comprehensive and effective disaster recovery plan that meets their specific needs and goals.")

        #Recommendations for "Do you have an incident response team available 24/7?"
        if answers["incidentResponseTeam"] == "no":
            recommendations.append("Consider having an incident response team available 24/7 to promptly respond to and manage security incidents.")

        #Recommendations for "Do you periodically test your Incident Response Plan with the incident handling team?"
        if answers["incidentResponsePlanTesting"] == "no":
            recommendations.append("Periodically test your incident response plan with the incident handling team to ensure readiness and effectiveness in the event of a security incident, see NIST guidence for further information (<a href='https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final'>NIST SP 800-34 Rev. 1</a>).")

        #Recommendations for "Do you have security tools (IDS, IPS, etc.) and processes in place to monitor use of information processing facilities and to take corrective action to respond to system irregularities/anomalies?"
        if answers["securityTools"] == "no":
            recommendations.append("Consider implementing security tools (such as IDS and IPS) and processes to monitor and respond to system irregularities or anomalies.(<a href='https://csrc.nist.rip/library/alt-SP800-94r1-draft.pdf'>NIST SP 800-94 Rev. 1</a>)")

        #Recommendations for "Does the organisation have Cyber insurance coverage?"
        if answers["cyberInsurance"] == "no":
            recommendations.append("Consider obtaining Cyber insurance coverage to protect your organisation from the financial impact of a cyber attack or data breach. Cyber insurance can help cover the costs of responding to and recovering from an incident, such as legal fees, public relations efforts, and any required notification and credit monitoring services for affected individuals. Having this type of coverage in place can provide peace of mind and help your organisation mitigate the potential financial impact of a cyber incident.")

        #Recommendations for "Does the organisation have data backups, are the backups logically or physically separated from source data and is it protected with the same controls as the source data?"
        if answers["dataBackups"] == "no":
            recommendations.append("Ensure that your organisation has data backups in place and that they are logically or physically separated from the source data and protected with the same controls as the source data. This is a key control reuired to achieve an ISO27001 certificate (<a href='https://www.isms.online/iso-27002/control-8-13-information-backup/'>ISO 27002:2022, Control 8.13 – Information Backup</a>) ") 
            
        #Recommendations for "Is Data destroyed or securely removed from IT assets prior to redeployment and at end of life?"
        if answers["dataRemoval"] == "no":
            recommendations.append("It's important to have a process in place to securely dispose of IT assets when they are no longer needed or at the end of their lifespan. One method to consider is using software such as Eraser or KillDisk to completely wipe the data from the asset. Another option is to physically destroy the asset, such as shredding hard drives or crushing computers. It's also important to ensure that this process is documented and followed consistently to ensure the security of sensitive data. This is a requirement of many security standards including ISO27001 and ITIL which can provide more in depth guidence (<a href='https://www.itil-docs.com/en-gb/blogs/asset-management/it-asset-management-process'>ITIL - IT Asset Management</a>). By implementing a secure asset disposal process, you can ensure that your company's data remains protected and minimise the risk of a data breach.")

        #Recommendations for "Do you monitor and limit the use of external devices (USB, CDs, etc.) to business need?"
        if answers["externalDevices"] == "no":
            recommendations.append("Consider implementing measures to monitor and limit the use of external devices, such as USBs and CDs. This can help to prevent unauthorised access to or transfer of sensitive data, as well as reduce the risk of malware infection. It may also be beneficial to establish a clear policy and procedures for the use of external devices, to ensure that all employees are aware of the proper protocols for handling them.")

        #Recommendations for "The cybersecurity architecture includes protections (such as full disk encryption) for data that is stored on assets that may be lost or stolen?"
        if answers["cybersecurityArchitecture"] == "no":
            recommendations.append("We reccomend adding protections for data stored on assets that may be lost or stolen. One effective measure is full disk encryption, which ensures that data on a device is unreadable without a decryption key. This can prevent unauthorised access to sensitive information in the event that an asset is lost or stolen. In addition, implementing a robust security architecture that includes multiple layers of protection can help to mitigate the risk of data loss or theft. Consider reviewing industry standards and best practices, such as (<a href='https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-111.pdf'>NIST SP 800-111</a>)")

        #Recommendations for "Does the company have an Information asset inventory that is up to date with the relevant information for asset management?"
        if answers["assetInventory"] == "no":
            recommendations.append("We reccomend that your company create an up-to-date information asset inventory to ensure effective asset management. This includes keeping track of all hardware and software assets, as well as any data stored on them. Having an accurate inventory allows a company to properly allocate resources and prioritise security measures. Consider reviewing the ITIL framework for more in depth guidence  more in depth guidence (<a href='https://www.itil-docs.com/en-gb/blogs/asset-management/it-asset-management-process'>ITIL - IT Asset Management</a>).")

        #Recommendations for "Does the company have network protection measures including monitoring, analysis and control of the network traffic (for example. firewalls, whitelisting, intrusion detection and prevention systems (IDPS)?"
        if answers["networkProtection"] == "no":
            recommendations.append("It is important for a company to have network protection measures in place, including monitoring, analysis, and control of network traffic. This can be achieved through the use of firewalls, whitelisting, and intrusion detection and prevention systems (IDPS). Implementing these measures can help to protect against cyber threats and ensure the security of the company's network. The (<a href='https://controls-assessment-specification.readthedocs.io/en/stable/control-13/index.html'>CIS Control 13: Network Monitoring and Defense</a>)Control can provide guidence on the implementation of network defencse techniques.")

        #Recommendations for "Is confidential data encrypted in transit and at rest?"
        if answers["confidentialDataEncryption"] == "no":
            recommendations.append("Consider encrypting confidential data in transit and at rest. The National Cyber Security Centre can provide guidence on how both can be accomplished (<a href='https://www.ncsc.gov.uk/collection/device-security-guidance/security-principles/protect-data-at-rest-and-in-transit'>NCSC</a>) ")

        #Recommendations for "Is the principle of least functionality enforced (for example, limiting services, limiting applications, limiting ports, limiting connected devices)?"
        if answers["leastFunctionality"] == "no":
            recommendations.append("We reccomend that your company implement the principle of least functionality by limiting services, applications, ports, and connected devices as appropriate. This principle is a common configuration management control seen in popular frameworks such as NIST -SP-800-53 and the Cloud Controls Matrix - (<a href='https://csf.tools/reference/nist-cybersecurity-framework/v1-1/pr/pr-pt/pr-pt-3/#ccm-v3-0-1'>CSF</a>) ")

        #Recommendations for "Are security applications embedded into endpoints (for example, mobile device management, endpoint detection and response applications, host-based firewalls)?"
        if answers["securityApplications"] == "no":
            recommendations.append("Consider implementing security applications, such as mobile device management and endpoint detection and response applications, on endpoints to enhance security. This is a requirement for organisations hoping to achieve ISO27001 certification. (<a href='https://www.isms.online/iso-27002/control-8-1-user-endpoint-devices/'>ISO 27002:2022, Control 8.1 – User Endpoint Devices</a>)")  
           
        #Recommendations for "Relevant threat information is gathered and cybersecurity vulnerability assessments are performed periodically and shared to stakeholders?"
        if answers["vulnerability_assessments"] == "no":
            recommendations.append("Gathering and sharing relevant threat information and cybersecurity vulnerability assessments can help protect against potential threats. Consider implementing a process for gathering and sharing this information with relevant stakeholders. (<a href='https://www.gov.uk/government/publications/cyber-threat-intelligence-information-sharing/cyber-threat-intelligence-information-sharing-guide'>GOV.uk</a>) provide guidence on this")

        #Recommendations for "A strategy for cyber risk management is established and maintained to implement and perform activities in the risk domain in alignment with the organisation's mission and objectives?"
        if answers["cyber_risk_management"] == "no":
            recommendations.append("Developing and maintaining a strategy for cyber risk management is essential for ensuring the security of your company's systems and data. This strategy should outline the steps that your company will take to manage risks and protect against potential threats, and should be aligned with your organisation's mission and objectives. Some best practices for developing a cyber risk management strategy include identifying and prioritising risks, establishing clear roles and responsibilities for managing risk, and implementing controls to mitigate identified risks. A resource that may be helpful in developing a cyber risk management strategy is (<a href='https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf'>NIST SP-800-30</a>)")

        #Recommendations for "Is there a program to manage the treatment of risks identified during assessments?"
        if answers["risk_management_program"] == "no":
            recommendations.append("Implementing a program to manage the treatment of identified risks can help protect against potential threats. Consider developing such a program using (<a href='https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf'>NIST SP-800-30</a>) guide") 
            
        #Recommendations for "Is there a formal process for assigning ownership, reviewing risk appetite, mapping controls and tracking the progress of risk mitigation strategies?"
        if answers["risk_mitigation_strategies"] == "no":
            recommendations.append("A process for managing risk, including assigning ownership, reviewing risk appetite, mapping controls, and tracking progress of risk mitigation strategies, can help protect against potential threats. We reccomend that this assessment be used as a starting point for managing identified risks.")

        #Recommendations for "Is there a vendor Management program?"
        if answers["vendor_management"] == "no":
            recommendations.append("Implementing a vendor management program is an important aspect of maintaining the security of your company's systems and data. As a starting point, consider reviewing vendors upon onboarding and passing them through a security check. Over time, you may also want to consider reviewing existing vendors annually. This is a requirement of the ISO 27001 standard and can help protect against supply chain threats (<a href='https://www.isms.online/iso-27001/annex-a-15-supplier-relationships/'>ISO 27001 – Annex A.15: Supplier Relationships</a>).")
            
        #Recommendations for "Is there a Human Resource policy approved by management, communicated to constituents and an owner to maintain and review?"  
        if answers["humanResourcePolicy"] == "no":
            recommendations.append("It is important to have a Human Resource policy in place that is approved by management, communicated to all constituents, and maintained and reviewed by a designated owner. This policy can help ensure that your organisation is in compliance with relevant laws and regulations, and that employee-related risks are effectively managed. Without such a policy, your organisation may be at increased risk of legal or regulatory non-compliance, as well as employee-related issues that could impact the security of your systems and data. We recommend implementing a Human Resource policy as soon as possible to mitigate these risks.")
    
        #Recommendations for "Are application development teams trained in secure coding techniques at least annually?"
        if answers["secureCoding"] == "no":
            recommendations.append("Training application development teams in secure coding techniques is an important aspect of maintaining the security of your organisation's systems and applications. Proper training can help reduce the risk of vulnerabilities and prevent potential threats. Without this training, your organisation may be at increased risk of security breaches or other issues related to insecure code. This is a critical Center for Internet Security (CIS)Control that should be implemented - (<a href='https://controls-assessment-specification.readthedocs.io/en/stable/control-16/control-16.9.html'>CIS Control 16: Application Software Security</a>)")

        #Recommendations for "Is security awareness training provided to employees at least annually?"
        if answers["securityAwareness"] == "no":
            recommendations.append("Security awareness training is an important part of maintaining the security of your organisation. By educating employees on potential threats and how to recognise and protect against them, you can help reduce the risk of security breaches and other security-related issues. Without this training, your employees may be more likely to inadvertently expose your organisation to potential threats. Please ensure this trainig is conducted att least annually. This is a critical Center for Internet Security (CIS)Control that should be implemented - (<a href='https://controls-assessment-specification.readthedocs.io/en/stable/control-14/index.html'>CIS Control 14: Security Awareness and Skills Training</a>)")
    
        #Recommendations for "Are background and reference checks conducted before hiring new employees?"
        if answers["backgroundChecks"] == "no":
            recommendations.append("Conducting background and reference checks before hiring new employees is an important aspect of maintaining the security of your organisation. These checks can help ensure that you are hiring trustworthy and reliable employees, and reduce the risk of employee-related threats. Without these checks, your organisation may be more vulnerable to insider threats or other issues related to hiring untrustworthy employees. We recommend implementing background and reference checks as part of your hiring process to mitigate these risks and ensure that you are hiring the best possible candidates.")

        #Recommendations for "Departmental cybersecurity responsibilities are identified and assigned to specific people in the organisation?"
        if answers["cybersecurityResponsibilities"] == "no":
            recommendations.append("Assigning cybersecurity responsibilities to specific people in the organisation is crucial for protecting against potential cyber-related threats. Without clear assignment, risks and incidents may go unidentified and unresolved. We recommend implementing this structure to enhance overall security of the organisation")    
            
        thirdPartyAssessment = answers["thirdPartyAssessment"]
        thirdPartyAssessmentRecommendations = {
            "no": "It is important to regularly gather security assessments of third parties, especially those that may have access to your organisation's data. These assessments can help you identify potential security risks and vulnerabilities, and can help you to make informed decisions about whether to continue doing business with a particular third party. We recommend implementing a process for conducting security assessments at least every 12 months.",
            "onboarding": "While conducting security assessments only on onboarding is a step in the right direction, it is important to keep in mind that security risks and vulnerabilities can change over time. We recommend conducting security assessments periodically at least every 12 months in order to stay aware of any changes and address them as they arise.",
            "12": "Performing security assessments on a yearly basis is a good practice, although it is important to keep in mind that the threat landscape can change rapidly, therefore it is important to stay aware of any emerging risks. We recommend monitoring your third party’s security posture  in addition to the yearly assessments.",
            "2": "Performing security assessments every 2 years can leave your organisation open to risks, as the threat landscape can change quickly. We recommend conducting security assessments at least every 12 months to stay aware of any changes and address them as they arise.",
            "2+": "Performing security assessments infrequently leaves your organisation open to risks, as the threat landscape can change quickly. We recommend conducting security assessments at least every 12 months to stay aware of any changes and address them as they arise.",
            "breach": "It is a good practice to conduct security assessments in the event of a third party security breach. It is also important to review your security practices and assess all your third parties at least once a year."
            }
        recommendations.append(thirdPartyAssessmentRecommendations[thirdPartyAssessment])
            
        #Recommendations for "Physical access controls (such as fences, locks, alarms and signage) are implemented and logs are maintained to determine who is allowed access and who has gained access to your on site premise?"
        if answers["physicalAccessControls"] == "no":
            recommendations.append("We reccomend implementing physical access controls, such as fences, locks, alarms, and signage, and maintaining logs to determine who is allowed access and who has gained access to your on-site premise is an important aspect of maintaining the security of your organisation's systems and data. It is often overlooked, but physical access to your premise is just as important as other security controls such as network security and data classification. Without these controls and logs in place, your organisation may be more vulnerable to unauthorised access, theft, or damage to your equipment and data. ")

        #Recommendations for "Do you have a formal change management process which includes impact analysis, approvals, testing, and rollback procedures?"
        if answers["changeManagementProcess"] == "no":
            recommendations.append("A formal change management process helps ensure that changes are properly planned, tested, and implemented with minimal disruption and risk to the organisation. We recommend implementing a formal change management process to safeguard against potential issues. (<a href='https://www.itil-docs.com/en-gb/blogs/news/itil-change-management-process'>ITIL Change Management Process</a>)Is an example guide to change management which includes impact analysis, approvals, testing, and rollback procedures.")

        #Recommendations for "Do you have documented security policies, including: Acceptable use, network security, data classification and User Identification, Authentication, and Authorisation?"
        if answers["documentedSecurityPolicies"] == "no":
            recommendations.append("It's important to have documented security policies in place to protect your organisation's systems and data from cyber threats. Without these policies, your organisation may be more vulnerable to security breaches and data loss. Use the results of this assessment as a starting point for identifying the necessary security policies and procedures that your organisation should have in place. Also, make sure to review existing policies and regulations and establish a team responsible for developing and maintaining the policies. Keep the policies clear and concise, and communicate them to all employees and provide training as necessary.")

        #Recommendations for "Have the policies been reviewed in the last 12 months?"
        if answers["policiesReviewed"] == "no":
            recommendations.append("It's important to regularly review and update your security policies to ensure they remain relevant and effective. The threat landscape is constantly changing, and it's important to make sure that your policies reflect the current risks and regulations. We recommend that you review your policies at least annually and make updates as needed.")
            
        #Recommendations for "physical access (such as keys, keycards, Identification badges) revoked when no longer needed?"
        if answers["physicalAccessRevoked"] == "no":
            recommendations.append("It's important to promptly revoke physical access when it is no longer needed. Unused keys, keycards, and identification badges can fall into the wrong hands, providing unauthorised individuals access to your organisation's facilities, increasing the risk of security breaches and loss of assets. This is a fundamental principle of security and is often a requirement of regulations such as ISO 27001, SOC2 and a (<a href='https://controls-assessment-specification.readthedocs.io/en/stable/control-6/control-6.2.html'>CIS Critical Security Control 6: Access Control Management</a>). We recommend implementing a process to automatically revoke access upon employee termination, and to regularly review and audit access permissions to ensure that only authorised individuals have access to your organisation's facilities.")

        #Recommendations for "Do you Process any personal Data? If so, are you GDPR compliant? If you do not process any, please select N/A."
        if answers["gdprCompliant"] == "no":
            recommendations.append("As your organisation processes personal data, it is important to ensure that you are in compliance with the  (<a href='https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/'>General Data Protection Regulation (GDPR)</a>). The GDPR imposes strict requirements on organisations that process personal data, including requirements for data protection, data security, and data breaches notification. Organisations that fail to comply with the GDPR may be subject to substantial fines. We recommend reviewing the GDPR requirements to ensure that your organisation's data protection and security practices meet the requirements set out in the GDPR, consult a GDPR lawyer for legal and technical advice, and develop a plan for addressing any gaps in your compliance.")      
            
        break

    #Return results to a template HTML document
    return render_template('results.html', company_name=company_name, recommendations=recommendations,percentage_risk_score=percentage_risk_score, output_message=output_message)
    
    #Close cursor and connection
    cursor.close()
    conn.close()
    
#Start Flask application in debug mode   
if __name__ == '__main__':
    app.debug = True
    app.run()
