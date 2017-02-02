# aac
Authentication and Authorization Control Module.

### Requirements
- MySQL 5.*+
- Java 1.7+
- Tomcat 7.*+

### Installation

1. **MySQL**
  1. Create a new schema (for example **acprovider**).
  2. Create a new user, (for example name **ac** password **ac**).
  3. Give the user all the privileges for the new schema.
2.  **Maven project**
  1. Set valid values, in the file **commoncore.properties**, for the following properties:
    1. Informations about a google account:
      - google.clientId
      - google.clientSecret
    2. Informations about a facebook account:
      - fb.clientId
      - fb.clientSecret
    3. Information about a mail account:
      - mail.username
      - mail.password
      - mail.host
      - mail.port
      - Mail.protocol
3. **Build**
  Run *mvn clean install* to produce aac.war
4. **Deployment**
  1. Deploy **aac.war** on Tomcat

### Use example

1. Login with **Google**.
2. Create a **New App**.
3. In **Settings**:
  1. Set **redirect Web server URLs** to *http://localhost*.
  2. Check **Server-side access, Browser access and Native app access**.
  3. In **Enabled identity providers**, check **google and googlelocal**.
4. In **Permissions**, check existing permissions or add new permissions.
