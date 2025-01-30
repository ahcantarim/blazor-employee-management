## Migration

1. Selecionar o projeto `Server` como projeto de inicialização.
1. No `Package Manager Console`, selecionar o projeto `ServerLibrary`.
1. Executar o comando `Add-Migration -o Data/Migrations` no `Package Manager Console`.
1. Informar o nome da Migration `First`.
1. Executar o comando `Update-Database` no `Package Manager Console`.
1. Verificar no `SQL Server Object Explorer` o banco de dados e as tabelas criadas.