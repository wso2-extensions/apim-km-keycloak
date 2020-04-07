# Integrate WSO2 API Store with an external IAM using the Keycloak Open Source IAM

In this guide, we explain how to integrate the WSO2 API Store with an external Identity and Access Management server (IAM) using the Keycloak Open Source IAM
to manage the OAuth clients and tokens required by WSO2 API Manager. This is a sample client implementation that consumes APIs exposed by Keycloak.
 
## Follow the instructions below to configure the third-party Key Manager

### Step 1 : Prerequisites

Download the Keycloak server 9.0.0 . Create a new realm to be used with WSO2 API Manager. This is where the clients will be created. 
Then create a new user and grant admin privileges inside the same realm to be able to invoke the Keycloak admin REST API. 

1. Go to the [Keycloak download page](https://www.keycloak.org/archive/downloads-9.0.0.html) and download the Standalone server distribution.
   
    ![alt text](images/download.png)
   
2. After Downloading extract the keycloak distribution to a location in the server. This extracted directory will be referred to as KEYCLOAK_HOME :

    1. Go to the <KEYCLOAK_HOME>/bin directory.
    2. Start up the Keycloak server by executing ./standalone.sh .
    
    ![alt text](images/start.png)

3. Create admin user and login :
    
    1. Provide credentials for an admin account which will be used to login to the management console.
    
    ![alt text](images/welcome.png)
    
    2. After the user account is successfully created. Login to the Administrator Console by following the link.
    
4. Create a new realm : 

    1. On the top of the left side bar menu, hover over 'Master' which corresponds to the master realm. Click on the Add Realm button which appears.
    2. Provide a name (e.g. apim) for the realm and click create. 
    
    ![alt_text](images/create_realm.png)
    
    3. A new realm will be created and you will be redirected to a settings page.
    
    ![alt_text](images/realm_settings.png)
    
5. Create a client and an admin user in the newly create realm to be used for admin API invocations.

    1. From the left menu click on Clients. Click the Create button on the upper right had side. 
    Provide the Client Id as apim-client and the Client Protocol as openid-connect.
    
    ![alt_text](images/create_client.png)
    
    2. From the left menu click on Users. Click the Add User button on the upper right had side. 
    Provide the username as apim-user and provide apim-password as password on the password tab.
    Make sure to turn off the Temporary field value.
    
    ![alt_text](images/create_user.png)
    
    ![alt_text](images/provide_password.png)
    
    3. Move to the Role Mappings tab and from the Client Role drop down select realm-management. Select all the roles and
    click on add selected.
    
    ![alt_text](images/role_mappings.png)    

### Step 2: Configure WSO2 API Manager

1. Download latest apim-keymanager-keycloak-x.x.x.jar from [here](https://github.com/wso2-extensions/apim-keymanager-keycloak/releases).
2. Copy that JAR file into the `<API-M_HOME>/repository/components/lib` directory.
3. Uncomment the `<APIKeyManager>` parameter in the `<API-M_HOME>/repository/conf/api-manager.xml` file. 
Change the values based on your third-party API.
>> **Note :** Replace the value of the `<keycloakInstanceUrl>` parameter with your Keycloak deployment's base URL.

>> **Note :** The `org.wso2.keycloak.client.KeycloakClient` class, mentioned in the following example, extends the Key Manager interface.

```xml
    <APIKeyManager>
       <KeyManagerClientImpl>org.wso2.keycloak.client.KeycloakClient</KeyManagerClientImpl>
       <Configuration>
         <keycloakInstanceUrl>http://localhost:8080</keycloakInstanceUrl>
         <keycloakRealmName>apim</keycloakRealmName>
         <client_id>apim-client</client_id>
         <username>apim-user</username>
         <password>apim-password</password>
       </Configuration>
    </APIKeyManager>
```
4.Comment out the grant types which are not supported by Keycloak by commenting out the ones other than implicit, authorization_code
client_credentials, password under the SupportedGrantTypes section in the identity.xml file which can be found under 
<APIM_HOME>/repository/conf/identity directory

### Step 3: Run the sample

You have connected WSO2 API Manager with a third-party Keycloak IAM server. Let's see how WSO2 API Manager creates OAuth clients in Keycloak, when applications are registered in the API Store.

1. Start **WSO2 API Manager**.
2. **Sign in to the WSO2 API Store :**
    1. Store UI :
       ![alt text](images/sign_in.png)
    2. cURL command :
        ```
        curl -k -X POST -c cookies https://localhost:9443/store/site/blocks/user/login/ajax/login.jag -d 'action=login&username=admin&password=admin'
        ```
        
3. **Create an application :**
    1. Store UI :
    
       Go to the API Store and click the **Applications tab**. Click **ADD APPLICATION** to create a new application.
       ![alt text](images/add_application.png)
    2. cURL command :
        ```
        curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/application/application-add/ajax/application-add.jag -d 'action=addApplication&application=keycloakClientApp&tier=Unlimited&description=&callbackUrl=https://www.google.lk'
        ```
        
4. **Generate an Application Key :** 
    
    Register an OAuth client in the Keycloak and generate the access token.
    1. Store UI :
       
       After creating an application, go to the **Production Keys** tab of the Application, then click the Generate Keys button.
       
       ![alt text](images/generate_keys.png)
       
       | Element | Description |
       | ------------- |-------------|
       | Application Grant Types (Mandatory) | Select the grant types for the application. |
       | Callback URL (Optional) | Redirection URI string for use in redirect-based flows. E.g., http://google.lk/ |
           
   2. cURL command :
      ```
      curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag -d 'action=generateApplicationKey&application=keycloakClientApp&authorizedDomains=ALL&keytype=PRODUCTION&validityTime=3600&callbackUrl=https://www.google.lk'
      ```
      
5. **Update the existing application :**
   
   1. Store UI: 
   
      Go back to the **Applications** page in the **WSO2 API Store**. Select the application to be edited. Click **EDIT**.
      ![alt text](images/edit_application.png)
      
   2. cURL command :
      ```
      curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/application/application-update/ajax/application-update.jag -d 'action=updateApplication&applicationOld=keycloakClientApp&applicationNew=keycloakClientAppNew&tier=Unlimited&descriptionNew=&callbackUrlNew=https://httpbin.org/get'
      ```
      
6. **Update grant types :**

    Edit the application details in Keycloak.
    
    1. Store UI: 
    
        Go to **Production Keys** tab of the Application, fill out the values to be updated and click **Update**.
        ![alt text](images/update_grants.png)
        
    2. cURL command :
        1. Write a JSON string with the required parameters. 

           E.g.,
            ``` json
            {"grant_types":"client_credentials,authorization_code"}'
            ```
        2. Use the above value for the jsonParams parameter as shown in the sample cURL command given below.
            ```
            curl 'https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag' -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=updateClientApplication&application=keycloakClientAppNew&keytype=PRODUCTION&callbackUrl=https://httpbin.org/get&jsonParams={"grant_types":"client_credentials,authorization_code,implicit,password"}' -k -b cookies
            ```
            
7. **Delete an OAuth Application :** 
    
    To delete an OAuth application in the Keycloak server, do the following.

    1. Store UI: 
        
        Go to the Applications page in the WSO2 API Store. Click Delete to delete your application.
        ![alt text](images/delete_application.png)
        
    2. cURL command :
        ```
        curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag -d 'action=deleteAuthApplication&consumerKey=admin_keycloakClientApp_PRODUCTION'
        ```
        
8. **Provision an Out-of-Band OAuth Client :** Provision an OAuth client created in the Okta server.
    
    Enable the option to provide out-of-band keys by opening the `<API-M_HOME>/repository/deployment/server/jaggeryapps/store/site/conf/site.json` file and changing the `"mapExistingAuthApps"` setting to `true`.

      > ``"mapExistingAuthApps" : true`
    
    1. Store UI : 
        
        After creating an application, go to the **Production Keys** tab of the Application.
    
         ![alt text](images/map_application.png)
    
        Click Provide Keys under Map Existing OAuth Keys.
        
         ![alt text](images/map_application_details.png)
    
         Fill out the required parameters and click Save. You will be redirected to the page that has application and access token details.
         
         >>**Note :** If you have not provide consumer secret, the access token will not be generated.
         

    2. cURL command :
        ```
        curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag -d 'action=mapExistingOauthClient&applicationName=keycloakClientApp&keytype=PRODUCTION&callbackUrl=https://www.google.lk&authorizedDomains=ALL&validityTime=3600&client_id=admin_keycloakClientApp_PRODUCTION&jsonParams={"username":"admin","key_type":"PRODUCTION","client_secret":"67ca04bb-1131-42ce-805d-58065b530823","validityPeriod":"3600", "tokenScope":"test", "tokenGrantType" : "client_credentials"}'
        ```
    
9. **Clean partially-created keys :**

    Clean any partially-created keys from the API Manager database, before adding a new subscription. Partially-created keys can remain in the API Manager databases when an OAuth application of a third-party Keycloak server gets deleted through the API Store UI. It only deletes the mapping that is maintained within API Manager.

    1. Store UI : 
    
        Go to the **Production Keys** tab of the Application and click **Clean up**.
    
        ![alt text](images/cleanup.png)
    2. cURL command :
    
        ```
        curl -k -X POST -b cookies https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag -d 'action=cleanUpApplicationRegistration&applicationName=keycloakClientAppNew&keyType=PRODUCTION'
        ```

10. **Re-generate the access token from the OAuth Provider :**
    1. Store UI : 
    
        Go to the **Production Keys** tab of the Application. Provide the token scope and click **Regenerate**.
        
        ![alt text](images/regenerate_token.png)
        
        >>**Note :** Please note down this token since this token will only be shown once. But you can always generate a new token.

    2. cURL command :
        1. Update the token endpoint in the `<API-M_HOME>/repository/deployment/server/synapse-configs/default/api/_TokenAPI_.xml` file accordingly.
            
            E.g., [http://localhost:8080/auth/realms/apim/protocol/openid-connect/token](http://localhost:8080/auth/realms/apim/protocol/openid-connect/token)
            
        2. Obtain a token from the OAuth Provider.
           Replace `<ConsumerKey:ConsumerSecret>` with the `Base64 encoded ConsumerKey:ConsumerSecret` of the client application you just created.
              ```
              curl -k -d "grant_type=client_credentials&scope=test" -H "Authorization: Basic <ConsumerKey:ConsumerSecret>" -H "Content-Type: application/x-www-form-urlencoded" https://localhost:8243/token
              ```
              
11. **Validate tokens by subscribing to the Keycloak client :**
    1. Sign in to the API Publisher and deploy the sample API (PizzaShackAPI), if you haven't done so already : 
        
        ![alt text](images/deploy_api.png)

    2. Assuming you still have the Keycloak client created earlier, subscribe to this API as follows :
        1. Store UI: 
        
            Select the application from the drop down menu and click Subscribe.
        
            ![alt text](images/subscribe_api.png)
              
        2. cURL command :
        
            ```
            curl -X POST -b cookies https://localhost:9443/store/site/blocks/subscription/subscription-add/ajax/subscription-add.jag -d 'action=addAPISubscription&name=PizzaShackAPI&version=1.0.0&provider=admin&tier=Unlimited&applicationName=keycloakClientApp'
            ```
    
    3. Invoke the API using the token obtained :
        
        1. Store UI: 
        
            Copy the Access Token that generated in the previous `step 4` or `step 8` or `step 10(b)` and paste it in the API Console UI as follows.
        
            ![alt text](images/invoke_api.png)
    
            You can invoke the API now.
            
        2. cURL command :
            ```
            curl -X GET --header 'Accept: application/json' --header 'Authorization: Bearer eyJraDH2LexQssMURzB56q78dmRa0NmDpH1o2FGYrVxCLeNcypJq6OlrzXw7N_R9H1f1OwH5GnT3pHssXjblr4qBKunIj6hRA0-lqHcwq3hcxusb2wgnUta_xudrUfXFn9bQXb5pkg' 'https://172.17.0.1:8243/pizzashack/1.0.0/menu'
            ```
            