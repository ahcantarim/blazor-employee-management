## Migration

1. Selecionar o projeto `Server` como projeto de inicialização.
1. No `Package Manager Console`, selecionar o projeto `ServerLibrary`.
1. Executar os comandos abaixo no `Package Manager Console`.
1. Posteriormente, verificar no `SQL Server Object Explorer` o banco de dados e as tabelas criadas.

### First model migration
```bash
> Add-Migration -o Data/Migrations
> First
> Update-Database
```

### Roles migration
```bash
> Add-Migration AddRoles
> Update-Database
```

### Refresh token migration
```bash
> Add-Migration AddRefreshTokens
> Update-Database
```