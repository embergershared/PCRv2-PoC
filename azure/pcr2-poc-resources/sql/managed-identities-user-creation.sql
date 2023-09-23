CREATE USER [webapp-win-use2-s4-pcr2-poc] FROM EXTERNAL PROVIDER WITH OBJECT_ID='c45180e2-XXX-YYY-72a03f8ebc59';
ALTER ROLE db_datareader ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
ALTER ROLE db_datawriter ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
ALTER ROLE db_ddladmin ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
GO




CREATE USER [func-app-use2-s4-pcr2-poc] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [func-app-use2-s4-pcr2-poc];
ALTER ROLE db_datawriter ADD MEMBER [func-app-use2-s4-pcr2-poc];
ALTER ROLE db_ddladmin ADD MEMBER [func-app-use2-s4-pcr2-poc];
GO
