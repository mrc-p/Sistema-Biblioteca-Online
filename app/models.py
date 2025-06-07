from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils import timezone

class Livro(models.Model):
    id = models.AutoField(primary_key=True)
    titulo = models.CharField(max_length=255)
    autor = models.CharField(max_length=255)
    isbn = models.CharField(max_length=20, unique=True, null=True)
    ano_publicacao = models.IntegerField(null=True)
    editora = models.CharField(max_length=100, null=True)
    quantidade_total = models.IntegerField()
    quantidade_disponivel = models.IntegerField()
    descricao = models.TextField(null=True)
    numero_paginas = models.IntegerField(null=True)
    genero = models.CharField(max_length=100, null=True)

    class Meta:
        db_table = 'livros'

class Exemplar(models.Model):
    STATUS_CHOICES = [
        ('disponivel', 'Disponível'),
        ('emprestado', 'Emprestado'),
        ('reservado', 'Reservado'),
        ('indisponivel', 'Indisponível'),
        ('perdido', 'Perdido'),
    ]

    id = models.AutoField(primary_key=True)
    id_livro = models.ForeignKey(Livro, on_delete=models.CASCADE, db_column='id_livro')
    codigo_barras = models.CharField(max_length=100, unique=True)
    status = models.CharField(
        max_length=50,
        choices=STATUS_CHOICES,
        default='disponivel'
    )
    class Meta:
        db_table = 'exemplares'

class UsuarioManager(BaseUserManager):
    def create_user(self, email, senha, **extra_fields):
        if not email:
            raise ValueError('O Email é obrigatório')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(senha)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, senha, **extra_fields):
        extra_fields.setdefault('tipo', 'administrador')
        return self.create_user(email, senha, **extra_fields)


class Usuario(AbstractBaseUser):
    id = models.AutoField(primary_key=True)
    nome = models.CharField(max_length=255)
    tipo = models.CharField(
        max_length=50,
        choices=[
            ('aluno', 'Aluno'),
            ('professor', 'Professor'),
            ('pesquisador', 'Pesquisador'),
            ('administrador', 'Administrador')
        ],
        default='aluno'
    )
    email = models.CharField(max_length=255, unique=True)
    telefone = models.CharField(max_length=20)
    password = models.CharField(max_length=255)
    

    punido_ate = models.DateField(null=True, blank=True)

    objects = UsuarioManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['nome', 'tipo']

    class Meta:
        db_table = 'usuarios'

    def __str__(self):
        return self.nome

class Emprestimo(models.Model):
    id = models.AutoField(primary_key=True)
    id_exemplar = models.IntegerField()
    id_usuario = models.IntegerField()
    data_emprestimo = models.DateField(default=timezone.now)
    data_devolucao_prevista = models.DateField()
    data_devolucao_real = models.DateField(null=True, blank=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('pendente', 'Pendente'),
            ('ativo', 'Ativo'),
            ('concluido', 'Concluído'),
            ('cancelado', 'Cancelado')
        ],
        null=True,
        blank=True
    )

    class Meta:
        db_table = 'emprestimos'

class Reserva(models.Model):
    id = models.AutoField(primary_key=True)
    id_exemplar = models.IntegerField()
    id_usuario = models.IntegerField()
    data_reserva = models.DateTimeField(default=timezone.now)
    status = models.CharField(
        max_length=30,
        choices=[
            ('pendente', 'Pendente'),
            ('aguardando_confirmacao', 'Aguardando Confirmação'),
            ('cancelada', 'Cancelada'),
            ('finalizada', 'Finalizada')
        ],
        null=True,
        blank=True
    )

    class Meta:
        db_table = 'reservas'

class RecursoDigital(models.Model):
    id = models.AutoField(primary_key=True)
    titulo = models.CharField(max_length=255)
    tipo = models.CharField(max_length=50)
    url = models.TextField()
    data_disponibilidade = models.DateField(null=True, blank=True)
    descricao = models.TextField(null=True, blank=True)
    numero_paginas = models.IntegerField(null=True, blank=True)
    genero = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        db_table = 'recursosdigitais'

class ListaLeitura(models.Model):
    id = models.AutoField(primary_key=True)
    nome = models.CharField(max_length=255)
    descricao = models.TextField(null=True, blank=True)
    id_usuario = models.IntegerField()

    class Meta:
        db_table = 'listasleitura'

class LivrosListasLeitura(models.Model):
    id_lista = models.IntegerField(primary_key=True) 
    id_livro = models.IntegerField()

    class Meta:
        
        db_table = 'livroslistasleitura'
        unique_together = (('id_lista', 'id_livro'),)
        constraints = [
            models.UniqueConstraint(fields=['id_lista', 'id_livro'], name='livroslistasleitura_pk')
        ]
    
class RecursosDigitaisListasLeitura(models.Model):
    id_lista = models.IntegerField(primary_key=True)  # Defina um dos campos como primary_key=True no model
    id_recurso_digital = models.IntegerField()

    class Meta:
        
        db_table = 'recursosdigitaislistasleitura'
        unique_together = (('id_lista', 'id_recurso_digital'),)
        constraints = [
            models.UniqueConstraint(fields=['id_lista', 'id_recurso_digital'], name='recursosdigitaislistasleitura_pk')
        ]

class HistoricoEmprestimo(models.Model):
    id = models.AutoField(primary_key=True)
    id_exemplar = models.IntegerField()
    id_usuario = models.IntegerField()
    data_emprestimo = models.DateField()
    data_devolucao_prevista = models.DateField()
    data_devolucao_real = models.DateField()
    data_registro_historico = models.DateTimeField()

    class Meta:
        db_table = 'historicoemprestimos'

class Favorito(models.Model):
    id = models.AutoField(primary_key=True)
    id_usuario = models.ForeignKey(
        Usuario,
        on_delete=models.CASCADE,
        db_column='id_usuario',
        related_name='favoritos'
    )
    id_livro = models.ForeignKey(
        Livro,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column='id_livro',
        related_name='favoritos'
    )
    id_recurso_digital = models.ForeignKey(
        RecursoDigital,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        db_column='id_recurso_digital',
        related_name='favoritos'
    )
    data_favoritado = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'favoritos'
        unique_together = (('id_usuario', 'id_livro', 'id_recurso_digital'),)
        constraints = [
            models.CheckConstraint(
                name='check_favorito_item',
                check=models.Q(id_livro__isnull=False) | models.Q(id_recurso_digital__isnull=False)
            ),
            models.CheckConstraint(
                name='check_favorito_exclusivo',
                check=~(models.Q(id_livro__isnull=False) & models.Q(id_recurso_digital__isnull=False))
            ),
        ]

    def __str__(self):
        return f'Favorito #{self.id} do usuário {self.id_usuario_id}'

class Notificacao(models.Model):
    id = models.AutoField(primary_key=True)
    usuario = models.ForeignKey('Usuario', on_delete=models.CASCADE)
    mensagem = models.TextField()
    lida = models.BooleanField(default=False)
    data_criacao = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'notificacoes'