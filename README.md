# Overview 
openLooKeng is a drop in engine which enables in-situ analytics on any data, anywhere, including geographically remote data sources. It provides a global view of all of your data via its SQL 2003 interface. With high availability, auto-scaling, built-in caching and indexing support, openLooKeng is ready for enterprise workload with required reliability.

openlookeng-ranger-plugin is a Ranger Plugin for openLooKeng to enable, monitor and manage comprehensive data security.

# Build Process

1. Check out the code from GIT repository

2. On the root folder, please execute the following Maven command:

```
mvn clean package
```

3. After the above build command execution, you would see the following TAR files in the target folder:

```
ranger-<ranger.version>-admin-openlookeng-<openlookeng.version>-plugin.tar.gz
ranger-<ranger.version>-openlookeng-<openlookeng.version>-plugin.tar.gz
```

# Deployment Process

## Install Ranger Admin plugin

1). Expand the ranger-&lt;ranger.version&gt;-admin-openlookeng-&lt;openlookeng.version&gt;-plugin.tar.gz file, you would see the following folders in the target folder:

```
openlookeng
service-defs
```

2). Register Service Type definition with Ranger

Service type definition should be registered with Ranger using REST API provided by Ranger Admin.  Once registered, Ranger Admin will provide UI to create service instances (called as repositories in previous releases) and policies for the service-type. Ranger plugin uses the service type definition and the policies to determine if an access request should be granted or not. The REST API can be invoked using curl command as shown in the example below:

```
curl -u admin:password -X POST -H "Accept: application/json" -H "Content-Type: application/json" -d @service-defs/ranger-servicedef-openlookeng.json http://ranger-admin-host:port/service/plugins/definitions
```

3). Copy openlookeng folder to ranger-plugins folder of Ranger Admin installed directory (e.g. ranger-&lt;ranger.version&gt;-admin/ews/webapp/WEB-INF/classes/ranger-plugins/)

## Install openLooKeng plugin

1). Expand the ranger-&lt;ranger.version&gt;-openlookeng-&lt;openlookeng.version&gt;-plugin.tar.gz file

2). Modify the install.properties file with appropriate variables. There is an example that some variables were modified as follows:

> ```properties
> # Location of Policy Manager URL
> # Example: POLICY_MGR_URL=http://policymanager.xasecure.net:6080
> POLICY_MGR_URL=http://xxx.xxx.xxx.xxx:6080
> 
> # This is the repository name created within policy manager
> # Example: REPOSITORY_NAME=openlookengdev
> REPOSITORY_NAME=openlookengdev
>
> # openLooKeng component installed directory
> # COMPONENT_INSTALL_DIR_NAME=../openlookeng
> COMPONENT_INSTALL_DIR_NAME=/home/hetu-server-1.0.1
>
> XAAUDIT.SOLR.ENABLE=false
> XAAUDIT.SUMMARY.ENABLE=false
> ```

3). Execute ./enable-openlookeng-plugin.sh

## Restart service

```
Restart Ranger Admin service: service ranger-admin restart
Restart openLooKeng service: ./launcher restart
```