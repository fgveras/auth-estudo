-- ------------------------------------------------------------
-- TABELA: Credores
-- ------------------------------------------------------------

CREATE TABLE Credores (
    Id              INT IDENTITY(1,1)   NOT NULL,
    Ativo           BIT                 NOT NULL DEFAULT 1,
    Nome            NVARCHAR(150)       NOT NULL,
    PessoaFisica    BIT                 NOT NULL DEFAULT 0,
    Recorrente      BIT                 NOT NULL DEFAULT 0,  -- Cobrança Recorrente?
    InstFinanceira  BIT                 NOT NULL DEFAULT 0,  -- É instituição financeira?
    CodInstFinanceira NVARCHAR(20)      NULL,                -- Código da instituição (ISPB, etc.)
    CriadoEm       DATETIME2           NOT NULL DEFAULT GETDATE(),
    AtualizadoEm   DATETIME2           NULL,
 
    CONSTRAINT PK_Credores PRIMARY KEY (Id)
);

-- ------------------------------------------------------------
-- TABELA: FormasPagamento
-- ------------------------------------------------------------
CREATE TABLE FormasPagamento (
    Id              INT IDENTITY(1,1)   NOT NULL,
    Ativo           BIT                 NOT NULL DEFAULT 1,
    Tipo            TINYINT             NOT NULL,            -- 1 = Crédito, 2 = Débito
    -- FK para Credores (filtrado por InstFinanceira = 1)
    CredorId        INT                 NULL,
    CriadoEm       DATETIME2           NOT NULL DEFAULT GETDATE(),
    AtualizadoEm   DATETIME2           NULL,
 
    CONSTRAINT PK_FormasPagamento PRIMARY KEY (Id),
    CONSTRAINT FK_FormasPagamento_Credor FOREIGN KEY (CredorId)
        REFERENCES Credores (Id),
    CONSTRAINT CK_FormasPagamento_Tipo CHECK (Tipo IN (1, 2))
);

-- ------------------------------------------------------------
-- TABELA: Gastos
-- ------------------------------------------------------------
CREATE TABLE Gastos (
    Id              INT IDENTITY(1,1)   NOT NULL,
    UserId          INT                 NOT NULL,
    Ativo           BIT                 NOT NULL DEFAULT 1,
    ValorTotal      DECIMAL(18, 2)      NOT NULL,
    -- Credor: FK com fallback texto livre
    CredorId        INT                 NULL,
    CredorTexto     NVARCHAR(150)       NULL,                -- fallback quando não há FK
    Motivo          NVARCHAR(300)       NULL,
    Parcelado       BIT                 NOT NULL DEFAULT 0,
    QtdParcelas     INT                 NULL,
    FormasPagamentoId INT               NULL,
    CriadoEm       DATETIME2           NOT NULL DEFAULT GETDATE(),
    AtualizadoEm   DATETIME2           NULL,
 
    CONSTRAINT PK_Gastos PRIMARY KEY (Id),
    CONSTRAINT FK_Gastos_User FOREIGN KEY (UserId)
        REFERENCES Users (Id),
    CONSTRAINT FK_Gastos_Credor FOREIGN KEY (CredorId)
        REFERENCES Credores (Id),
    CONSTRAINT FK_Gastos_FormaPagamento FOREIGN KEY (FormasPagamentoId)
        REFERENCES FormasPagamento (Id),
    -- Pelo menos um dos dois deve ser preenchido
    CONSTRAINT CK_Gastos_Credor CHECK (CredorId IS NOT NULL OR CredorTexto IS NOT NULL),
    -- Parcelas só faz sentido se Parcelado = 1
    CONSTRAINT CK_Gastos_Parcelas CHECK (
        Parcelado = 0 OR (Parcelado = 1 AND QtdParcelas IS NOT NULL AND QtdParcelas > 1)
    )
)

-- ------------------------------------------------------------
-- TABELA: PerfilFinanceiro (extensão de Users)
-- Dados financeiros/pessoais do usuário
-- ------------------------------------------------------------
CREATE TABLE PerfilFinanceiro (
    Id              INT IDENTITY(1,1)   NOT NULL,
    UserId          INT                 NOT NULL,
    Ativo           BIT                 NOT NULL DEFAULT 1,
    NomeCompleto    NVARCHAR(200)       NOT NULL,
    CPF             CHAR(11)            NULL,                -- apenas dígitos
    Idade           TINYINT             NULL,
    Email           NVARCHAR(200)       NULL,
    SalarioBruto    DECIMAL(18, 2)      NULL,
    SalarioLiquido  DECIMAL(18, 2)      NULL,
    CriadoEm       DATETIME2           NOT NULL DEFAULT GETDATE(),
    AtualizadoEm   DATETIME2           NULL,
 
    CONSTRAINT PK_PerfilFinanceiro PRIMARY KEY (Id),
    CONSTRAINT FK_PerfilFinanceiro_User FOREIGN KEY (UserId)
        REFERENCES Users (Id),
    CONSTRAINT UQ_PerfilFinanceiro_User UNIQUE (UserId),    -- 1 perfil por user
    CONSTRAINT UQ_PerfilFinanceiro_CPF  UNIQUE (CPF)
);