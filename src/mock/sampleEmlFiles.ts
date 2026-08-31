export interface SampleEmailScenario {
  id: string;
  name: string;
  category: 'BEC' | 'Phishing' | 'Malware' | 'Clean';
  badgeLabel: string;
  description: string;
  rawEmlContent: string;
  fileName: string;
  targetAnalysisId: string;
}

export const sampleEmailScenarios: SampleEmailScenario[] = [
  {
    id: 'scenario-bec-wire',
    name: 'Scenario 1: CEO Urgent Escrow Wire Transfer (BEC)',
    category: 'BEC',
    badgeLabel: 'CRITICAL BEC',
    description: 'Executive impersonation demanding urgent $485,000 wire with strict confidentiality and Tor exit origin.',
    fileName: 'urgent-escrow-wire-transfer.eml',
    targetAnalysisId: 'EML-2026-001',
    rawEmlContent: `Received: from tor-exit-04.flokinet.is (185.220.101.54) by mail-edge-relay.hostroyale.net
    with ESMTPSA id q991a for <finance-ops@enterprise-corp.com>; Sat, 29 Aug 2026 18:18:02 +0000
Received: from mail-edge-relay.hostroyale.net (193.148.16.4) by relay-nl-02.serverius.net
    with ESMTPS id n112b; Sat, 29 Aug 2026 18:18:45 +0000
Received: from relay-nl-02.serverius.net (91.240.118.172) by mx-inbound-01.enterprise-corp.com
    with TLSv1.3; Sat, 29 Aug 2026 18:19:30 +0000
Authentication-Results: mx-inbound-01.enterprise-corp.com;
    spf=fail (sender IP 185.220.101.54) smtp.mailfrom=bounce-daemon@corp-bankofamerica.xyz;
    dkim=fail header.d=corp-bankofamerica.xyz header.s=default;
    dmarc=fail (p=reject sp=reject) header.from=corp-bankofamerica.xyz
From: "David Stirling - CEO" <ceo@corp-bankofamerica.xyz>
To: finance-ops@enterprise-corp.com, treasury@enterprise-corp.com
CC: d.stirling.private@protonmail.com
Reply-To: d.stirling.executive@corp-bankofamerica.xyz
Subject: URGENT: Confidential Acquisition Escrow Wire Transfer (#ACQ-9921)
Date: Sat, 29 Aug 2026 18:20:14 +0000
Message-ID: <20260829182014.9921.8492@corp-bankofamerica.xyz>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_9921_8492"

------=_Part_9921_8492
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

Hi Marcus,

I am currently in an all-day confidential executive board session regarding the Project Titan acquisition. We need to immediately execute an urgent escrow deposit of $485,000 to secure the binding agreement before 5:00 PM EST today.

Please confirm you can handle this wire immediately from our primary corporate operating account. Due to strict SEC non-disclosure regulations, DO NOT discuss this via phone or our internal Slack channels until public filing on Monday.

Attached are the revised SWIFT wiring details for JPMorgan Chase Escrow Services.

Wire Information:
Beneficiary: Apex Strategic Holdings LLC (Escrow Trustee)
Bank: JPMorgan Chase NA, New York
Account: 8829-1029-4401
Routing: 021000021
Reference: ACQ-TITAN-ESCROW-CONFIDENTIAL

Please process immediately and reply to this email with the wire transaction confirmation PDF.

Verify portal: https://secure-bank-login.xyz/auth/verify?session=99281a

Regards,
David Stirling
Chief Executive Officer
Enterprise Global Corporation
------=_Part_9921_8492--`,
  },
  {
    id: 'scenario-m365-phish',
    name: 'Scenario 2: Microsoft 365 MFA Expiration Phish',
    category: 'Phishing',
    badgeLabel: 'CREDENTIAL HARVEST',
    description: 'Typosquatted domain imitating Microsoft security team threatening account suspension.',
    fileName: 'mfa-security-alert.eml',
    targetAnalysisId: 'EML-2026-002',
    rawEmlContent: `Received: from relay-nl-02.serverius.net (91.240.118.172) by mail-edge-proxy.com
    with ESMTPS; Sat, 29 Aug 2026 16:44:00 +0000
Authentication-Results: mail-edge-proxy.com;
    spf=fail (sender IP 91.240.118.172) smtp.mailfrom=bounce@micros0ft-security-verify.com;
    dkim=none;
    dmarc=fail (p=none) header.from=micros0ft-security-verify.com
From: "Microsoft 365 Security Team" <security-alerts@micros0ft-security-verify.com>
To: all-staff@enterprise-corp.com
Subject: ACTION REQUIRED: Multifactor Authentication (MFA) Session Expiring Within 2 Hours
Date: Sat, 29 Aug 2026 16:45:10 +0000
Message-ID: <mfa.notice.202608291645@micros0ft-security-verify.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your Microsoft 365 corporate account session is scheduled for automatic deactivation due to mandatory tenant security key rotation.

Failure to re-authenticate within 2 hours will result in suspension of email, OneDrive, and SharePoint access.

Click below to verify your identity and retain active credentials:
https://micros0ft-security-verify.com/login.srf?tenant=enterprise-corp

Microsoft Security Operations Center
One Microsoft Way, Redmond, WA`,
  },
  {
    id: 'scenario-supplier-trojan',
    name: 'Scenario 3: Fake Supplier Overdue Invoice (Malware Trojan)',
    category: 'Malware',
    badgeLabel: 'SUPPLY CHAIN MALWARE',
    description: 'Spoofed vendor overdue notice carrying double-extension VBScript Trojan downloader.',
    fileName: 'overdue-invoice-notice.eml',
    targetAnalysisId: 'EML-2026-003',
    rawEmlContent: `Received: from dynamic-pool-lagos.mtn.ng (197.210.55.13) by mx1.supplier-invoices-pay.net;
    Sat, 29 Aug 2026 14:10:00 +0000
Authentication-Results: mx1.supplier-invoices-pay.net;
    spf=pass (sender IP 197.210.55.13) smtp.mailfrom=bounce@supplier-invoices-pay.net;
    dkim=pass header.d=supplier-invoices-pay.net;
    dmarc=pass header.from=supplier-invoices-pay.net
From: "Global Logistics Billing" <billing@supplier-invoices-pay.net>
To: accounts-payable@enterprise-corp.com
Subject: OVERDUE INVOICE NOTICE: #INV-2026-8819 Final Settlement
Date: Sat, 29 Aug 2026 14:12:00 +0000
Message-ID: <inv8819.202608291412@supplier-invoices-pay.net>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_Invoice_8819"

------=_Part_Invoice_8819
Content-Type: text/plain; charset=UTF-8

Dear Accounts Payable Team,

Please find attached the past due statement for Invoice #INV-2026-8819 regarding August Freight Consolidations ($64,200.00).

Our bank details have changed starting this quarter. Please verify the new banking information in the attached PDF invoice and confirm transaction date.

Global Logistics Settlement Team
------=_Part_Invoice_8819
Content-Type: application/x-vbs; name="Invoice_INV_8819_Revised_Account.pdf.vbs"
Content-Disposition: attachment; filename="Invoice_INV_8819_Revised_Account.pdf.vbs"
Content-Transfer-Encoding: base64

J3Zic2NyaXB0IG1hbHdhcmUgcGF5bG9hZCBzaW11bGF0aW9u...
------=_Part_Invoice_8819--`,
  },
  {
    id: 'scenario-legit-board',
    name: 'Scenario 4: Authentic Executive Strategy Meeting (Clean Baseline)',
    category: 'Clean',
    badgeLabel: 'VERIFIED CLEAN',
    description: 'Legitimate internal executive communication with 100% cryptographic authentication pass.',
    fileName: 'q3-executive-agenda.eml',
    targetAnalysisId: 'EML-2026-009',
    rawEmlContent: `Received: from mail-relay.google.com (142.250.180.26) by inbound-01.legitimate-enterprise.com
    with TLSv1.3; Fri, 28 Aug 2026 09:59:00 +0000
Authentication-Results: inbound-01.legitimate-enterprise.com;
    spf=pass (sender IP 142.250.180.26) smtp.mailfrom=j.hayes@legitimate-enterprise.com;
    dkim=pass (google) header.d=legitimate-enterprise.com;
    dmarc=pass (p=reject sp=reject) header.from=legitimate-enterprise.com
From: "Jonathan Hayes - COO" <j.hayes@legitimate-enterprise.com>
To: exec-committee@legitimate-enterprise.com
Subject: Q3 Executive Strategy Review Agenda & Key Deliverables
Date: Fri, 28 Aug 2026 10:00:00 +0000
Message-ID: <q3.agenda.202608281000@legitimate-enterprise.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Executive Committee,

Attached is the finalized agenda for next Thursday's Q3 Strategic Review meeting in Boardroom 4B.

Please review the strategic priorities and reach out if you have any questions ahead of time.

Best regards,
Jonathan Hayes
Chief Operating Officer`,
  },
];
