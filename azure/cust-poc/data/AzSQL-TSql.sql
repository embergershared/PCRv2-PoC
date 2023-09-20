CREATE USER [webapp-win-use2-s4-pcr2-poc] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
ALTER ROLE db_datawriter ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
ALTER ROLE db_ddladmin ADD MEMBER [webapp-win-use2-s4-pcr2-poc];
GO




CREATE USER [func-app-use2-s4-pcr2-poc] FROM EXTERNAL PROVIDER;
ALTER ROLE db_datareader ADD MEMBER [func-app-use2-s4-pcr2-poc];
ALTER ROLE db_datawriter ADD MEMBER [func-app-use2-s4-pcr2-poc];
ALTER ROLE db_ddladmin ADD MEMBER [func-app-use2-s4-pcr2-poc];
GO
