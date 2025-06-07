from django.shortcuts import render
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from reportlab.lib.pagesizes import A4
from django.db.models import F, ExpressionWrapper, DurationField
from reportlab.pdfgen import canvas
from io import BytesIO
from django.http import HttpResponse
from rest_framework import status
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import date, datetime
from django.db.models import Q
from app.utils import criar_notificacao
from django.core.exceptions import ValidationError
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiResponse, OpenApiParameter, OpenApiExample, OpenApiTypes
import re
from .models import (Livro, Exemplar, Usuario, Emprestimo, Reserva, RecursoDigital, ListaLeitura, LivrosListasLeitura,
    RecursosDigitaisListasLeitura, HistoricoEmprestimo, Favorito, Notificacao
)
from .serializers import (LivroSerializer, ExemplarSerializer, UsuarioSerializer, EmprestimoSerializer, ReservaSerializer,
    RecursoDigitalSerializer, ListaLeituraSerializer, LivrosListasLeituraSerializer, RecursosDigitaisListasLeituraSerializer,
    HistoricoEmprestimoSerializer, FavoritoSerializer, NotificacaoSerializer
)
from django.shortcuts import redirect

def home(request):
    return redirect('/swagger/')


TIPOS_VALIDOS = ['aluno', 'professor', 'pesquisador', 'administrador']

@extend_schema(
    summary="Registrar um novo usuário",
    description=(
        "Permite o registro de novos usuários. "
        "Apenas administradores autenticados podem registrar novos administradores. "
    ),
    tags=["Registrar"],
    request=UsuarioSerializer,
    examples=[
        OpenApiExample(
            name="Exemplo de registro de usuário",
            value={
                "nome": "Ana Lima",
                "tipo": "aluno",
                "email": "ana@example.com",
                "telefone": "(11) 91234-5678",
                "password": "minhasenha123",
                "punido_ate": None
            },
            request_only=True
        )
    ],
    responses={
        201: OpenApiResponse(
            description="Usuário registrado com sucesso",
            response=UsuarioSerializer,
            examples=[
                OpenApiExample(
                    name="Resposta 201 - Sucesso",
                    value={
                        "id": 1,
                        "nome": "Ana Lima",
                        "tipo": "aluno",
                        "email": "ana@example.com",
                        "telefone": "(11) 91234-5678",
                        "punido_ate": None
                    },
                    response_only=True
                )
            ]
        ),
        400: OpenApiResponse(description="Dados inválidos"),
        403: OpenApiResponse(description="Acesso negado ao registrar administrador"),
        500: OpenApiResponse(description="Erro interno")
    }
)
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([AllowAny])
def registro_usuario(request):
    try:
        dados = request.data.copy()

        for campo in ['nome', 'email', 'tipo']:
            if campo in dados and isinstance(dados[campo], str):
                dados[campo] = dados[campo].strip().lower()

        tipo = dados.get('tipo', 'aluno')

        if tipo not in TIPOS_VALIDOS:
            return Response({"erro": f"Tipo de usuário inválido. Tipos válidos: {', '.join(TIPOS_VALIDOS)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        if tipo == 'administrador':
            if not request.user.is_authenticated or getattr(request.user, 'tipo', '') != 'administrador':
                return Response({"erro": "Apenas administradores autenticados podem registrar outros administradores."},
                                status=status.HTTP_403_FORBIDDEN)

        if Usuario.objects.filter(email=dados.get('email')).exists():
            return Response({"erro": "Já existe um usuário com este email."}, status=status.HTTP_400_BAD_REQUEST)

        email_regex = r"[^@]+@[^@]+\.[^@]+"
        if not re.match(email_regex, dados.get('email', '')):
            return Response({"erro": "Email inválido."}, status=status.HTTP_400_BAD_REQUEST)

        if 'password' in dados:
            if len(dados['password']) < 6:
                return Response({"erro": "A senha deve ter pelo menos 6 caracteres."}, status=status.HTTP_400_BAD_REQUEST)
            dados['password'] = make_password(dados['password'])

        serializer = UsuarioSerializer(data=dados)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "mensagem": "Usuário registrado com sucesso.",
                "dados": serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"erro": "Erro interno ao registrar usuário.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="Login de usuário",
        description="Realiza login com email e senha, retornando tokens JWT e dados do usuário.",
        tags=["Login"],
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "email": {"type": "string", "example": "usuario@email.com"},
                    "password": {"type": "string", "example": "sua_senha_segura"}
                },
                "required": ["email", "password"]
            }
        },
        responses={
            200: OpenApiResponse(
                description="Login bem-sucedido. Tokens JWT e dados do usuário retornados.",
                examples=[
                    OpenApiExample(
                        "Resposta de sucesso",
                        value={
                            "mensagem": "Login bem-sucedido.",
                            "refresh": "token_refresh_exemplo",
                            "access": "token_access_exemplo",
                            "usuario": {
                                "id": 1,
                                "nome": "João da Silva",
                                "email": "joao@email.com",
                                "tipo": "leitor"
                            }
                        },
                        status_codes=["200"]
                    )
                ]
            ),
            400: OpenApiResponse(description="Email e/ou senha ausentes."),
            401: OpenApiResponse(description="Senha incorreta."),
            404: OpenApiResponse(description="Usuário não encontrado."),
            500: OpenApiResponse(description="Erro interno no login.")
        }
    )
)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_usuario(request):
    try:
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"erro": "Email e senha são obrigatórios."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            usuario = Usuario.objects.get(email=email)
        except Usuario.DoesNotExist:
            return Response({"erro": "Usuário não encontrado."}, status=status.HTTP_404_NOT_FOUND)

        if not usuario.check_password(password):
            return Response({"erro": "Senha incorreta."}, status=status.HTTP_401_UNAUTHORIZED)

        refresh = RefreshToken.for_user(usuario)
        return Response({
            "mensagem": "Login bem-sucedido.",
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "usuario": {
                "id": usuario.id,
                "nome": usuario.nome,
                "email": usuario.email,
                "tipo": usuario.tipo
            }
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            {"erro": "Erro interno no login.", "detalhes": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema_view(
    get=extend_schema(
        summary="Listar todos os livros ou obter um por ID",
        parameters=[],
        tags=["Livros"], 
        responses={
            200: OpenApiResponse(description="Lista de livros ou livro específico", response=LivroSerializer(many=True)),
            401: OpenApiResponse(description="Não autenticado"),
            404: OpenApiResponse(description="Livro não encontrado")
        },
    ),
    post=extend_schema(
        summary="Criar um novo livro",
        request=LivroSerializer,
        tags=["Livros"],
        responses={
            201: OpenApiResponse(description="Livro adicionado com sucesso", response=LivroSerializer),
            400: OpenApiResponse(description="Erro de validação ou campos faltando"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
        },
    ),
    put=extend_schema(
        summary="Atualizar um livro existente (requer ID)",
        request=LivroSerializer,
        parameters=[
            OpenApiParameter(
                name='id',
                required=True,
                type=int,
                location=OpenApiParameter.PATH,
                description="ID do livro a ser atualizado"
            ),
        ],
        tags=["Livros"],
        responses={
            200: OpenApiResponse(description="Livro atualizado com sucesso", response=LivroSerializer),
            400: OpenApiResponse(description="Erro de validação"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Livro não encontrado")
        },
    ),
    delete=extend_schema(
        summary="Excluir um livro (requer ID)",
        parameters=[
            OpenApiParameter(
                name='id',
                required=True,
                type=int,
                location=OpenApiParameter.PATH,
                description="ID do livro a ser deletado"
            ),
        ],
        tags=["Livros"],
        responses={
            204: OpenApiResponse(description="Livro deletado com sucesso"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Livro não encontrado")
        },
    ),
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def livro_manager(request, id=None):
    try:
        if request.method == 'GET':
            if id:
                livro = Livro.objects.get(id=id)
                serializer = LivroSerializer(livro)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                livros = Livro.objects.all()
                serializer = LivroSerializer(livros, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem adicionar livros."}, status=status.HTTP_403_FORBIDDEN)

            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            dados = request.data.copy()

            campos_necessarios = ['titulo', 'autor', 'ano_publicacao', 'qtd_paginas', 'editora']
            for campo in campos_necessarios:
                if campo not in dados or not str(dados[campo]).strip():
                    return Response({"erro": f"O campo '{campo}' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
                dados[campo] = str(dados[campo]).strip()

            try:
                dados['ano_publicacao'] = int(dados['ano_publicacao'])
                dados['qtd_paginas'] = int(dados['qtd_paginas'])
            except ValueError:
                return Response({
                    "erro": "Os campos 'ano_publicacao' e 'qtd_paginas' devem ser números inteiros válidos."
                }, status=status.HTTP_400_BAD_REQUEST)

            serializer = LivroSerializer(data=dados)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Livro adicionado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem atualizar livros."}, status=status.HTTP_403_FORBIDDEN)

            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            livro = Livro.objects.get(id=id)
            dados = request.data.copy()

            if 'ano_publicacao' in dados:
                try:
                    dados['ano_publicacao'] = int(dados['ano_publicacao'])
                except ValueError:
                    return Response({"erro": "'ano_publicacao' deve ser um número inteiro."}, status=status.HTTP_400_BAD_REQUEST)

            if 'qtd_paginas' in dados:
                try:
                    dados['qtd_paginas'] = int(dados['qtd_paginas'])
                except ValueError:
                    return Response({"erro": "'qtd_paginas' deve ser um número inteiro."}, status=status.HTTP_400_BAD_REQUEST)
                
            for campo in ['titulo', 'autor', 'editora']:
                if campo in dados:
                    dados[campo] = str(dados[campo]).strip()

            serializer = LivroSerializer(livro, data=dados, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Livro atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem deletar livros."}, status=status.HTTP_403_FORBIDDEN)

            if not id:
                return Response({"erro": "ID é obrigatório para exclusão."}, status=status.HTTP_400_BAD_REQUEST)

            livro = Livro.objects.get(id=id)
            livro.delete()
            return Response({"mensagem": "Livro deletado com sucesso."}, status=status.HTTP_204_NO_CONTENT)

    except Livro.DoesNotExist:
        return Response({"erro": "Livro não encontrado."}, status=status.HTTP_404_NOT_FOUND)

    except ValidationError as ve:
        return Response({"erro": "Erro de validação nos dados.", "detalhes": str(ve)}, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar usuários (todos se for administrador, ou apenas o próprio se não for)",
        parameters=[],
        tags=["Usuários"],
        responses={
            200: UsuarioSerializer(many=True),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Usuário não encontrado")
        }
    ),
    put=extend_schema(
        summary="Atualizar um usuário (requer ID). Apenas administradores podem alterar o campo 'punido_ate'.",
        description=(
            "Permite atualizar um usuário específico. Usuários comuns só podem atualizar seus próprios dados. "
            "**Apenas administradores** podem alterar `punido_ate`."
        ),
        parameters=[
            OpenApiParameter(
                name='id',
                type=int,
                location=OpenApiParameter.PATH,
                required=True,
                description="ID do usuário"
            )
        ],
        tags=["Usuários"],
        request=UsuarioSerializer,
        responses={
            200: OpenApiResponse(description="Usuário atualizado com sucesso", response=UsuarioSerializer),
            400: OpenApiResponse(description="Erro de validação"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Usuário não encontrado")
        }
    ),
    delete=extend_schema(
        summary="Excluir um usuário (requer ID)",
        parameters=[
            OpenApiParameter(
                name='id',
                type=int,
                location=OpenApiParameter.PATH,
                required=True,
                description="ID do usuário"
            )
        ],
        tags=["Usuários"],
        responses={
            204: OpenApiResponse(description="Usuário deletado com sucesso"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Usuário não encontrado")
        }
    )
)
@api_view(['GET', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def usuario_manager(request, id=None):
    try:
        if request.method == 'GET':
            if id is not None:
                usuario = Usuario.objects.get(id=id)
                if request.user.tipo != 'administrador' and usuario.id != request.user.id:
                    return Response(
                        {"erro": "Você não tem permissão para ver este usuário."},
                        status=status.HTTP_403_FORBIDDEN
                    )
                serializer = UsuarioSerializer(usuario)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                if request.user.tipo == 'administrador':
                    usuarios = Usuario.objects.all()
                    serializer = UsuarioSerializer(usuarios, many=True)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                else:
                    serializer = UsuarioSerializer(request.user)
                    return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'PUT':
            if id is None:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            usuario = Usuario.objects.get(id=id)

            if request.user.tipo != 'administrador' and usuario.id != request.user.id:
                return Response({"erro": "Você não tem permissão para atualizar este usuário."},
                                status=status.HTTP_403_FORBIDDEN)

            dados = request.data.copy()

            if 'id' in dados:
                dados.pop('id')

            campos_string = ['nome', 'email', 'telefone', 'tipo']
            for campo in campos_string:
                if campo in dados and isinstance(dados[campo], str):
                    dados[campo] = dados[campo].strip()

            if 'email' in dados:
                email_regex = r"[^@]+@[^@]+\.[^@]+"
                if not re.match(email_regex, dados['email']):
                    return Response({"erro": "Email inválido."}, status=status.HTTP_400_BAD_REQUEST)

            if 'tipo' in dados:
                if request.user.tipo != 'administrador':
                    dados.pop('tipo')
                else:
                    TIPOS_VALIDOS = ['aluno', 'professor', 'pesquisador', 'administrador']
                    if dados['tipo'] not in TIPOS_VALIDOS:
                        return Response(
                            {"erro": f"Tipo de usuário inválido. Deve ser um de: {', '.join(TIPOS_VALIDOS)}."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    
            if 'punido_ate' in dados and request.user.tipo != 'administrador':
                dados.pop('punido_ate')

            if 'password' in dados:
                if dados['password']:
                    if len(dados['password']) < 6:
                        return Response({"erro": "A senha deve ter pelo menos 6 caracteres."},
                                        status=status.HTTP_400_BAD_REQUEST)
                    dados['password'] = make_password(dados['password'])
                else:
                    dados.pop('password')

            serializer = UsuarioSerializer(usuario, data=dados, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Usuário atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({
                "erro": "Erro de validação.",
                "mensagem": "Alguns campos estão inválidos.",
                "detalhes": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if id is None:
                return Response({"erro": "ID é obrigatório para exclusão."},
                                status=status.HTTP_400_BAD_REQUEST)

            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem excluir usuários."},
                                status=status.HTTP_403_FORBIDDEN)

            usuario = Usuario.objects.get(id=id)
            usuario.delete()

            return Response({"mensagem": "Usuário deletado com sucesso."}, status=status.HTTP_204_NO_CONTENT)

    except Usuario.DoesNotExist:
        return Response({"erro": "Usuário não encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response(
            {"erro": "Erro interno do servidor.", "detalhes": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@extend_schema_view(
    get=extend_schema(
        summary="Listar todos os exemplares ou obter um por ID",
        parameters=[],
        tags=["Exemplares"],
        responses={
            200: ExemplarSerializer(many=True),
            401: OpenApiResponse(description="Não autenticado"),
            404: OpenApiResponse(description="Exemplar não encontrado")
        }
    ),
    post=extend_schema(
        summary="Adicionar um novo exemplar",
        request=ExemplarSerializer,
        tags=["Exemplares"],
        responses={
            201: OpenApiResponse(description="Exemplar adicionado com sucesso", response=ExemplarSerializer),
            400: OpenApiResponse(description="Erro de validação ou campos obrigatórios ausentes"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Apenas administradores podem adicionar exemplares"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um exemplar (requer ID)",
        request=ExemplarSerializer,
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID do exemplar a ser atualizado"),
        ],
        tags=["Exemplares"],
        responses={
            200: OpenApiResponse(description="Exemplar atualizado com sucesso", response=ExemplarSerializer),
            400: OpenApiResponse(description="Erro de validação ou dados inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Apenas administradores podem atualizar exemplares"),
            404: OpenApiResponse(description="Exemplar não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Excluir um exemplar (requer ID)",
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID do exemplar a ser deletado"),
        ],
        tags=["Exemplares"],
        responses={
            204: OpenApiResponse(description="Exemplar deletado com sucesso"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Apenas administradores podem deletar exemplares"),
            404: OpenApiResponse(description="Exemplar não encontrado"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def exemplar_manager(request, id=None):
    try:
        if request.method == 'GET':
            if id:
                exemplar = Exemplar.objects.get(id=id)
                serializer = ExemplarSerializer(exemplar)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                exemplares = Exemplar.objects.all()
                serializer = ExemplarSerializer(exemplares, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem adicionar exemplares."}, status=status.HTTP_403_FORBIDDEN)

            dados = request.data.copy()
        
            for campo in ['codigo_barras', 'status']:
                if campo in dados and isinstance(dados[campo], str):
                    dados[campo] = dados[campo].strip()

            if not dados.get('id_livro'):
                return Response({"erro": "O campo 'id_livro' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
            if not dados.get('codigo_barras'):
                return Response({"erro": "O campo 'codigo_barras' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
            if not dados.get('status'):
                return Response({"erro": "O campo 'status' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

            try:
                Livro.objects.get(id=dados['id_livro'])
            except Livro.DoesNotExist:
                return Response({"erro": "Livro com o id fornecido não existe."}, status=status.HTTP_400_BAD_REQUEST)
            
            if dados['status'] not in ['disponivel', 'emprestado', 'reservado']:
                return Response({"erro": "Status inválido. Use: 'disponivel', 'emprestado' ou 'reservado'."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ExemplarSerializer(data=dados)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Exemplar adicionado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({
                "erro": "Dados inválidos.",
                "detalhes": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem atualizar exemplares."}, status=status.HTTP_403_FORBIDDEN)

            if not id:
                return Response({
                    "erro": "ID do exemplar é obrigatório para atualização."
                }, status=status.HTTP_400_BAD_REQUEST)

            exemplar = Exemplar.objects.get(id=id)
            dados = request.data.copy()

            for campo in ['codigo_barras', 'status']:
                if campo in dados and isinstance(dados[campo], str):
                    dados[campo] = dados[campo].strip()

            if 'id_livro' in dados:
                try:
                    Livro.objects.get(id=dados['id_livro'])
                except Livro.DoesNotExist:
                    return Response({"erro": "Livro com o id fornecido não existe."}, status=status.HTTP_400_BAD_REQUEST)

            if 'status' in dados and dados['status'] not in ['disponivel', 'emprestado', 'reservado']:
                return Response({"erro": "Status inválido. Use: 'disponivel', 'emprestado' ou 'reservado'."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ExemplarSerializer(exemplar, data=dados, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Exemplar atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({
                "erro": "Dados inválidos.",
                "detalhes": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem deletar exemplares."}, status=status.HTTP_403_FORBIDDEN)

            if not id:
                return Response({
                    "erro": "ID do exemplar é obrigatório para exclusão."
                }, status=status.HTTP_400_BAD_REQUEST)

            exemplar = Exemplar.objects.get(id=id)
            exemplar.delete()
            return Response({
                "mensagem": "Exemplar deletado com sucesso."
            }, status=status.HTTP_204_NO_CONTENT)

    except Exemplar.DoesNotExist:
        return Response({"erro": "Exemplar não encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            "erro": "Erro interno do servidor.",
            "detalhes": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar todos os empréstimos (para administradores) ou listar os empréstimos próprios dos demais usuários",
        description=(
            "Se for administrador, lista todos os empréstimos.\n"
            "Se for aluno, professor ou pesquisador, lista apenas os seus próprios empréstimos."
        ),
        parameters=[],
        tags=["Empréstimos"],
        responses={
            200: OpenApiResponse(description="Lista de empréstimos retornada com sucesso", response=EmprestimoSerializer),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            404: OpenApiResponse(description="Empréstimo não encontrado"),
        }
    ),
    post=extend_schema(
        summary="Registrar um novo empréstimo",
        description=(
            "Usuários comuns informam apenas id_exemplar e data_devolucao_prevista.\n"
            "data_emprestimo e status são definidos automaticamente.\n"
            "O prazo máximo é de até 20 dias a partir da data do empréstimo.\n"
            "Administradores podem criar empréstimos para qualquer usuário."
        ),
        request=EmprestimoSerializer,
        tags=["Empréstimos"],
        responses={
            201: OpenApiResponse(description="Empréstimo registrado com sucesso", response=EmprestimoSerializer),
            400: OpenApiResponse(description="Erro de validação nos dados enviados ou regras de negócio não atendidas"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Usuário punido ou sem permissão"),
            404: OpenApiResponse(description="Usuário ou exemplar não encontrado"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um empréstimo existente",
        description=(
            "Administradores podem atualizar qualquer campo.\n"
            "Usuários comuns podem atualizar apenas o campo data_devolucao_prevista "
            "quando o empréstimo está com status pendente, respeitando o limite de até 20 dias após a data do empréstimo."
        ),
        request=EmprestimoSerializer,
        parameters=[
            OpenApiParameter(
                name='id',
                required=True,
                type=int,
                location=OpenApiParameter.PATH,
                description="ID do empréstimo a ser atualizado"
            ),
        ],
        tags=["Empréstimos"],
        responses={
            200: OpenApiResponse(description="Empréstimo atualizado com sucesso", response=EmprestimoSerializer),
            400: OpenApiResponse(description="Dados inválidos para atualização ou regras de negócio não atendidas"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Atualização não permitida ou acesso negado"),
            404: OpenApiResponse(description="Empréstimo não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Cancelar um empréstimo",
        description=(
            "Administradores podem cancelar qualquer empréstimo.\n"
            "Usuários comuns podem cancelar apenas empréstimos com status pendente e que sejam seus."
        ),
        parameters=[
            OpenApiParameter(
                name='id',
                required=True,
                type=int,
                location=OpenApiParameter.PATH,
                description="ID do empréstimo a ser deletado"
            ),
        ],
        tags=["Empréstimos"],
        responses={
            204: OpenApiResponse(description="Empréstimo deletado com sucesso"),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado ou empréstimo não pode ser cancelado"),
            404: OpenApiResponse(description="Empréstimo não encontrado"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def emprestimo_manager(request, id=None):
    try:
        usuario = request.user
        is_admin = usuario.tipo == 'administrador'

        if request.method == 'GET':
            emprestimos = Emprestimo.objects.all() if is_admin else Emprestimo.objects.filter(id_usuario=usuario.id)
            if id:
                emprestimo = emprestimos.filter(id=id).first()
                if not emprestimo:
                    return Response({"erro": "Empréstimo não encontrado."}, status=status.HTTP_404_NOT_FOUND)
                return Response(EmprestimoSerializer(emprestimo).data)
            return Response(EmprestimoSerializer(emprestimos, many=True).data)

        elif request.method == 'POST':
            data = request.data.copy()

            if not is_admin:
                campos_proibidos = ['id_usuario', 'data_emprestimo', 'status', 'data_devolucao_real']
                campos_enviados = [campo for campo in campos_proibidos if campo in data]
                if campos_enviados:
                    return Response({
                        "erro": "Você não tem permissão para enviar os seguintes campos: " + ", ".join(campos_enviados)
                    }, status=status.HTTP_403_FORBIDDEN)

                if usuario.punido_ate and usuario.punido_ate > date.today():
                    return Response({"erro": f"Usuário punido até {usuario.punido_ate.strftime('%d/%m/%Y')}."},
                                    status=status.HTTP_403_FORBIDDEN)
                data['id_usuario'] = usuario.id

            else:
                if 'id_usuario' not in data:
                    return Response({"erro": "O campo 'id_usuario' é obrigatório para administradores."},
                                    status=status.HTTP_400_BAD_REQUEST)

            if 'id_exemplar' not in data or 'data_devolucao_prevista' not in data:
                return Response({"erro": "Campos 'id_exemplar' e 'data_devolucao_prevista' são obrigatórios."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                exemplar = Exemplar.objects.get(id=int(data['id_exemplar']))
                if exemplar.status != 'disponivel':
                    return Response({"erro": "O exemplar não está disponível para empréstimo."},
                                    status=status.HTTP_400_BAD_REQUEST)
            except Exemplar.DoesNotExist:
                return Response({"erro": "Exemplar não encontrado."}, status=status.HTTP_404_NOT_FOUND)

            data['data_emprestimo'] = date.today()
            data['status'] = 'pendente'

            try:
                data_prevista = datetime.strptime(data['data_devolucao_prevista'], "%Y-%m-%d").date()
            except ValueError:
                return Response({"erro": "Formato inválido para data_devolucao_prevista. Use YYYY-MM-DD."},
                                status=status.HTTP_400_BAD_REQUEST)

            if (data_prevista - date.today()).days > 20:
                return Response({"erro": "A data_devolucao_prevista deve ser no máximo 20 dias a partir de hoje."},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = EmprestimoSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                exemplar.status = 'emprestado'
                exemplar.save()
                return Response({"mensagem": "Empréstimo registrado com sucesso.", "dados": serializer.data},
                                status=status.HTTP_201_CREATED)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if not id:
                return Response({"erro": "ID do empréstimo é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

            emprestimo = Emprestimo.objects.filter(id=id).first()
            if not emprestimo:
                return Response({"erro": "Empréstimo não encontrado."}, status=status.HTTP_404_NOT_FOUND)

            dados = request.data.copy()

            if not is_admin:
                if emprestimo.id_usuario != usuario.id:
                    return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)
                if emprestimo.status != 'pendente':
                    return Response({"erro": "Só é possível atualizar empréstimos com status 'pendente'."}, status=status.HTTP_403_FORBIDDEN)

                campos_proibidos = ['data_emprestimo', 'id', 'id_usuario', 'id_exemplar', 'status', 'data_devolucao_real']
                campos_enviados = [campo for campo in campos_proibidos if campo in dados]
                if campos_enviados:
                    return Response({
                        "erro": "Você não tem permissão para alterar os seguintes campos: " + ", ".join(campos_enviados)
                    }, status=status.HTTP_403_FORBIDDEN)

                if 'data_devolucao_prevista' in dados:
                    try:
                        data_prevista = datetime.strptime(dados['data_devolucao_prevista'], "%Y-%m-%d").date()
                    except ValueError:
                        return Response({"erro": "Formato inválido para data_devolucao_prevista. Use YYYY-MM-DD."},
                                        status=status.HTTP_400_BAD_REQUEST)

                    if (data_prevista - emprestimo.data_emprestimo).days > 20:
                        return Response({"erro": "A data_devolucao_prevista deve ser no máximo 20 dias após a data do empréstimo."},
                                        status=status.HTTP_400_BAD_REQUEST)

            serializer = EmprestimoSerializer(emprestimo, data=dados, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({"mensagem": "Empréstimo atualizado com sucesso.", "dados": serializer.data})
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if not id:
                return Response({"erro": "ID do empréstimo é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

            emprestimo = Emprestimo.objects.filter(id=id).first()
            if not emprestimo:
                return Response({"erro": "Empréstimo não encontrado."}, status=status.HTTP_404_NOT_FOUND)

            if not is_admin:
                if emprestimo.id_usuario != usuario.id:
                    return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)
                if emprestimo.status != 'pendente':
                    return Response({"erro": "Só é possível cancelar empréstimos com status 'pendente'."}, status=status.HTTP_403_FORBIDDEN)

            emprestimo.delete()
            return Response({"mensagem": "Empréstimo deletado com sucesso."}, status=status.HTTP_204_NO_CONTENT)

    except Exception as e:
        return Response({"erro": "Erro interno no servidor.", "detalhes": str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar todas as reservas ou buscar uma reserva por ID",
        parameters=[],
        tags=["Reservas"],
        responses={
            200: ReservaSerializer(many=True),
            400: OpenApiResponse(description="ID inválido."),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado a esta reserva."),
            404: OpenApiResponse(description="Reserva não encontrada."),
            500: OpenApiResponse(description="Erro interno do servidor."),
        }
    ),
    post=extend_schema(
        summary="Registrar uma nova reserva",
        request=ReservaSerializer,
        tags=["Reservas"],
        responses={
            201: OpenApiResponse(description="Reserva adicionada com sucesso.", response=ReservaSerializer),
            400: OpenApiResponse(description="Dados inválidos ou incompletos."),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Usuário sem permissão para criar reserva para outro usuário."),
            500: OpenApiResponse(description="Erro interno do servidor."),
        }
    ),
    put=extend_schema(
        summary="Atualizar uma reserva existente",
        parameters=[
            OpenApiParameter(
                name='id',
                description='ID da reserva a ser atualizada',
                required=True,
                type=int,
                location=OpenApiParameter.PATH
            ),
        ],
        tags=["Reservas"],
        request=ReservaSerializer,
        responses={
            200: OpenApiResponse(description="Reserva atualizada com sucesso.", response=ReservaSerializer),
            400: OpenApiResponse(description="ID inválido ou dados inválidos."),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Sem permissão para alterar esta reserva."),
            404: OpenApiResponse(description="Reserva não encontrada."),
            500: OpenApiResponse(description="Erro interno do servidor."),
        }
    ),
    delete=extend_schema(
        summary="Cancelar uma reserva",
        parameters=[
            OpenApiParameter(
                name='id',
                description='ID da reserva a ser cancelada',
                required=True,
                type=int,
                location=OpenApiParameter.PATH
            ),
        ],
        tags=["Reservas"],
        responses={
            200: OpenApiResponse(description="Reserva cancelada com sucesso."),
            400: OpenApiResponse(description="ID inválido ou status da reserva não permite cancelamento."),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Sem permissão para cancelar esta reserva."),
            404: OpenApiResponse(description="Reserva não encontrada."),
            500: OpenApiResponse(description="Erro interno do servidor."),
        }
    ),
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def reserva_manager(request, id=None):
    usuario = request.user

    try:
        if request.method == 'GET':
            if id:
                try:
                    id = int(id)
                except ValueError:
                    return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

                reserva = Reserva.objects.get(id=id)

                if usuario.tipo != 'administrador' and reserva.id_usuario != usuario.id:
                    return Response({"erro": "Acesso negado a esta reserva."}, status=status.HTTP_403_FORBIDDEN)

                serializer = ReservaSerializer(reserva)
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:
                if usuario.tipo == 'administrador':
                    reservas = Reserva.objects.all()
                else:
                    reservas = Reserva.objects.filter(id_usuario=usuario.id)

                serializer = ReservaSerializer(reservas, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            data = request.data.copy()

            id_exemplar = data.get('id_exemplar')
            if not id_exemplar:
                return Response({"erro": "O campo 'id_exemplar' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                data['id_exemplar'] = int(id_exemplar)
            except ValueError:
                return Response({"erro": "ID do exemplar deve ser um número inteiro."}, status=status.HTTP_400_BAD_REQUEST)

            if usuario.tipo != 'administrador':
                data['id_usuario'] = usuario.id
            else:
                id_usuario = data.get('id_usuario')
                if not id_usuario:
                    return Response({"erro": "O campo 'id_usuario' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
                try:
                    data['id_usuario'] = int(id_usuario)
                except ValueError:
                    return Response({"erro": "ID do usuário deve ser um número inteiro."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = ReservaSerializer(data=data, context={'request': request})
            if serializer.is_valid():
                reserva = serializer.save()
                reserva.status = 'pendente'
                reserva.save()

                criar_notificacao(
                    usuario_id=reserva.id_usuario,
                    mensagem="Sua reserva foi registrada e será processada quando um exemplar estiver disponível."
                )

                return Response({
                    "mensagem": "Reserva adicionada com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                id = int(id)
            except ValueError:
                return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

            reserva = Reserva.objects.get(id=id)

            if usuario.tipo != 'administrador' and reserva.id_usuario != usuario.id:
                return Response({"erro": "Você não tem permissão para alterar esta reserva."}, status=status.HTTP_403_FORBIDDEN)

            data = request.data.copy()

            if 'status' in data:
                status_reserva = data['status'].strip().lower()
                if status_reserva not in ['pendente', 'aguardando_confirmacao', 'cancelada', 'finalizada']:
                    return Response({"erro": "Status de reserva inválido."}, status=status.HTTP_400_BAD_REQUEST)
                data['status'] = status_reserva

            serializer = ReservaSerializer(reserva, data=data, partial=True, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Reserva atualizada com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if not id:
                return Response({"erro": "ID é obrigatório para cancelamento."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                id = int(id)
            except ValueError:
                return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

            reserva = Reserva.objects.get(id=id)

            if usuario.tipo != 'administrador' and reserva.id_usuario != usuario.id:
                return Response({"erro": "Você não tem permissão para cancelar esta reserva."}, status=status.HTTP_403_FORBIDDEN)

            if reserva.status not in ['pendente', 'aguardando_confirmacao']:
                return Response({"erro": "A reserva já está cancelada ou finalizada."}, status=status.HTTP_400_BAD_REQUEST)

            reserva.status = 'cancelada'
            reserva.save()

            return Response({"mensagem": "Reserva cancelada com sucesso."}, status=status.HTTP_200_OK)

    except Reserva.DoesNotExist:
        return Response({"erro": "Reserva não encontrada."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@extend_schema_view(
    get=extend_schema(
        summary="Listar todos os recursos digitais ou buscar um por ID",
        parameters=[],
        tags=["Recursos Digitais"],
        responses={
            200: RecursoDigitalSerializer(many=True),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            404: OpenApiResponse(description="Recurso Digital não encontrado")
        }
    ),
    post=extend_schema(
        summary="Registrar um novo recurso digital (apenas administradores)",
        request=RecursoDigitalSerializer,
        tags=["Recursos Digitais"],
        responses={
            201: OpenApiResponse(description="Recurso Digital registrado com sucesso", response=RecursoDigitalSerializer),
            400: OpenApiResponse(description="Erro de validação nos dados enviados"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado. Apenas administradores podem realizar esta operação"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um recurso digital existente (apenas administradores)",
        request=RecursoDigitalSerializer,
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID do recurso digital a ser atualizado"),
        ],
        tags=["Recursos Digitais"],
        responses={
            200: OpenApiResponse(description="Recurso Digital atualizado com sucesso", response=RecursoDigitalSerializer),
            400: OpenApiResponse(description="Dados inválidos para atualização"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado. Apenas administradores podem realizar esta operação"),
            404: OpenApiResponse(description="Recurso Digital não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Excluir um recurso digital (apenas administradores)",
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID do recurso digital a ser deletado"),
        ],
        tags=["Recursos Digitais"],
        responses={
            204: OpenApiResponse(description="Recurso Digital deletado com sucesso"),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado. Apenas administradores podem realizar esta operação"),
            404: OpenApiResponse(description="Recurso Digital não encontrado"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def recurso_digital_manager(request, id=None):
    try:
        usuario = request.user

        if request.method == 'GET':
            if id:
                try:
                    id = int(id)
                except ValueError:
                    return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

                recurso_digital = RecursoDigital.objects.get(id=id)
                serializer = RecursoDigitalSerializer(recurso_digital)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                recursos_digitais = RecursoDigital.objects.all()
                serializer = RecursoDigitalSerializer(recursos_digitais, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        if usuario.tipo != 'administrador':
            return Response({"erro": "Acesso negado. Apenas administradores podem realizar esta operação."},
                            status=status.HTTP_403_FORBIDDEN)

        if request.method == 'POST':
            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            data = request.data.copy()

            campos_obrigatorios = ['titulo', 'tipo', 'url']
            for campo in campos_obrigatorios:
                if not data.get(campo):
                    return Response({"erro": f"O campo '{campo}' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)
                data[campo] = str(data[campo]).strip()

            serializer = RecursoDigitalSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Recurso Digital adicionado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                id = int(id)
            except ValueError:
                return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

            recurso_digital = RecursoDigital.objects.get(id=id)

            data = request.data.copy()
            for campo in ['titulo', 'tipo', 'url']:
                if campo in data:
                    data[campo] = str(data[campo]).strip()

            serializer = RecursoDigitalSerializer(recurso_digital, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Recurso Digital atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if not id:
                return Response({"erro": "ID é obrigatório para exclusão."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                id = int(id)
            except ValueError:
                return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

            recurso_digital = RecursoDigital.objects.get(id=id)
            recurso_digital.delete()
            return Response({"mensagem": "Recurso Digital deletado com sucesso."}, status=status.HTTP_204_NO_CONTENT)

    except RecursoDigital.DoesNotExist:
        return Response({"erro": "Recurso Digital não encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar todas as listas de leitura ou buscar uma por ID",
        description=(
            "Usuários comuns podem listar e acessar apenas suas próprias listas. "
            "Administradores podem listar e acessar todas."
        ),
        tags=["Listas de Leitura"],
        responses={
            200: ListaLeituraSerializer(many=True),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Lista de Leitura não encontrada"),
        }
    ),
    post=extend_schema(
        summary="Criar nova lista de leitura",
        description=(
            "Usuários comuns criam listas para si mesmos. "
            "Administradores podem especificar `id_usuario`. "
            "Campo obrigatório: `nome`."
        ),
        request=ListaLeituraSerializer,
        tags=["Listas de Leitura"],
        responses={
            201: OpenApiResponse(description="Criada com sucesso", response=ListaLeituraSerializer),
            400: OpenApiResponse(description="Dados inválidos ou campo obrigatório ausente"),
            401: OpenApiResponse(description="Não autenticado"),
        }
    ),
    put=extend_schema(
        summary="Atualizar uma lista de leitura",
        description=(
            "Usuários comuns podem atualizar suas próprias listas. "
            "Administradores podem atualizar qualquer lista."
        ),
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID da lista de leitura a ser atualizada")
        ],
        request=ListaLeituraSerializer,
        tags=["Listas de Leitura"],
        responses={
            200: OpenApiResponse(description="Atualizada com sucesso", response=ListaLeituraSerializer),
            400: OpenApiResponse(description="Dados inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Lista de Leitura não encontrada"),
        }
    ),
    delete=extend_schema(
        summary="Deletar uma lista de leitura",
        description=(
            "Usuários comuns podem deletar suas próprias listas. "
            "Administradores podem deletar qualquer lista."
        ),
        parameters=[
            OpenApiParameter(name='id', required=True, type=int, location=OpenApiParameter.PATH,
                             description="ID da lista de leitura a ser deletada")
        ],
        tags=["Listas de Leitura"],
        responses={
            204: OpenApiResponse(description="Deletada com sucesso"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Lista de Leitura não encontrada"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def lista_leitura_manager(request, id=None):
    try:
        usuario = request.user
        is_admin = usuario.tipo == 'administrador'

        if id:
            try:
                id = int(id)
            except ValueError:
                return Response({"erro": "ID inválido."}, status=status.HTTP_400_BAD_REQUEST)

        if request.method == 'GET':
            if id:
                lista_leitura = ListaLeitura.objects.get(id=id)
                if not is_admin and lista_leitura.id_usuario != usuario.id:
                    return Response({"erro": "Você não tem permissão para acessar esta lista."},
                                    status=status.HTTP_403_FORBIDDEN)
                serializer = ListaLeituraSerializer(lista_leitura)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                listas = ListaLeitura.objects.all() if is_admin else ListaLeitura.objects.filter(id_usuario=usuario.id)
                listas = listas.order_by('nome')
                serializer = ListaLeituraSerializer(listas, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            data = request.data.copy()

            if 'nome' in data:
                data['nome'] = str(data['nome']).strip()
            else:
                return Response({"erro": "O campo 'nome' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

            if not is_admin:
                data['id_usuario'] = usuario.id
            else:
                if 'id_usuario' not in data:
                    data['id_usuario'] = usuario.id

            serializer = ListaLeituraSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Lista de Leitura criada com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            lista_leitura = ListaLeitura.objects.get(id=id)

            if not is_admin and lista_leitura.id_usuario != usuario.id:
                return Response({"erro": "Você não tem permissão para atualizar esta lista."},
                                status=status.HTTP_403_FORBIDDEN)

            data = request.data.copy()
            if 'nome' in data:
                data['nome'] = str(data['nome']).strip()

            serializer = ListaLeituraSerializer(lista_leitura, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Lista de Leitura atualizada com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if not id:
                return Response({"erro": "ID é obrigatório para exclusão."}, status=status.HTTP_400_BAD_REQUEST)

            lista_leitura = ListaLeitura.objects.get(id=id)

            if not is_admin and lista_leitura.id_usuario != usuario.id:
                return Response({"erro": "Você não tem permissão para deletar esta lista."},
                                status=status.HTTP_403_FORBIDDEN)

            lista_leitura.delete()
            return Response({"mensagem": "Lista de Leitura deletada com sucesso."},
                            status=status.HTTP_204_NO_CONTENT)

    except ListaLeitura.DoesNotExist:
        return Response({"erro": "Lista de Leitura não encontrada."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        
@extend_schema_view(
    get=extend_schema(
        summary="Listar livros de uma lista de leitura ou buscar um livro específico na lista",
        description=(
            "Usuários comuns podem listar os livros apenas das suas próprias listas. "
            "Administradores podem listar todos os livros de qualquer lista. "
            "Se `id_lista` e `id_livro` forem fornecidos, busca o livro específico na lista."
        ),
        tags=["Livros em Listas de Leitura"],
        responses={
            200: OpenApiResponse(description="Lista de livros retornada com sucesso"),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Lista ou livro não encontrado"),
        }
    ),
    post=extend_schema(
        summary="Adicionar um livro a uma lista de leitura",
        description=(
            "Usuários comuns só podem adicionar livros às suas próprias listas. "
            "Administradores podem adicionar a qualquer lista. "
            "Campos obrigatórios: `id_lista` e `id_livro`."
        ),
        tags=["Livros em Listas de Leitura"],
        request=LivrosListasLeituraSerializer,
        responses={
            201: OpenApiResponse(description="Livro adicionado com sucesso"),
            400: OpenApiResponse(description="Dados inválidos ou campos obrigatórios ausentes"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
        }
    ),
    put=extend_schema(
        summary="Atualizar dados de um livro em uma lista de leitura",
        description=(
            "Usuários comuns só podem atualizar livros nas suas próprias listas. "
            "Administradores podem atualizar em qualquer lista. "
            "IDs de `id_lista` e `id_livro` são obrigatórios na URL."
        ),
        tags=["Livros em Listas de Leitura"],
        request=LivrosListasLeituraSerializer,
        parameters=[
            OpenApiParameter(name='id_lista', required=True, type=int, location=OpenApiParameter.PATH),
            OpenApiParameter(name='id_livro', required=True, type=int, location=OpenApiParameter.PATH),
        ],
        responses={
            200: OpenApiResponse(description="Registro atualizado com sucesso"),
            400: OpenApiResponse(description="Dados inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Registro não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Remover um livro de uma lista de leitura",
        description=(
            "Usuários comuns só podem remover livros das suas próprias listas. "
            "Administradores podem remover de qualquer lista."
        ),
        tags=["Livros em Listas de Leitura"],
        parameters=[
            OpenApiParameter(name='id_lista', required=True, type=int, location=OpenApiParameter.PATH),
            OpenApiParameter(name='id_livro', required=True, type=int, location=OpenApiParameter.PATH),
        ],
        responses={
            204: OpenApiResponse(description="Livro removido da lista com sucesso"),
            400: OpenApiResponse(description="IDs obrigatórios não fornecidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Registro não encontrado"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def livros_listas_leitura_manager(request, id_lista=None, id_livro=None):
    user = request.user
    is_admin = user.tipo == 'administrador'

    try:
        if id_lista is not None:
            try:
                id_lista = int(id_lista)
            except ValueError:
                return Response({"erro": "id_lista inválido. Deve ser inteiro."},
                                status=status.HTTP_400_BAD_REQUEST)

        if id_livro is not None:
            try:
                id_livro = int(id_livro)
            except ValueError:
                return Response({"erro": "id_livro inválido. Deve ser inteiro."},
                                status=status.HTTP_400_BAD_REQUEST)

        lista = None
        if id_lista is not None:
            try:
                lista = ListaLeitura.objects.get(id=id_lista)
            except ListaLeitura.DoesNotExist:
                return Response({"erro": "Lista de Leitura não encontrada."},
                                status=status.HTTP_404_NOT_FOUND)

            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

        if request.method == 'GET':
            if id_lista and id_livro:
                try:
                    registro = LivrosListasLeitura.objects.get(id_lista=id_lista, id_livro=id_livro)
                    serializer = LivrosListasLeituraSerializer(registro)
                    return Response(serializer.data, status=status.HTTP_200_OK)
                except LivrosListasLeitura.DoesNotExist:
                    return Response({"erro": "Livro não encontrado na lista."},
                                    status=status.HTTP_404_NOT_FOUND)

            elif id_lista:
                registros = LivrosListasLeitura.objects.filter(id_lista=id_lista)
                serializer = LivrosListasLeituraSerializer(registros, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:
                if is_admin:
                    registros = LivrosListasLeitura.objects.all()
                else:
                    listas_ids = ListaLeitura.objects.filter(id_usuario=user.id).values_list('id', flat=True)
                    registros = LivrosListasLeitura.objects.filter(id_lista__in=listas_ids)

                serializer = LivrosListasLeituraSerializer(registros, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        if request.method == 'POST':
            data = request.data.copy()

            if 'id_lista' not in data or 'id_livro' not in data:
                return Response({"erro": "Campos 'id_lista' e 'id_livro' são obrigatórios."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                data['id_lista'] = int(data['id_lista'])
                data['id_livro'] = int(data['id_livro'])
            except ValueError:
                return Response({"erro": "IDs devem ser números inteiros."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                lista = ListaLeitura.objects.get(id=data['id_lista'])
            except ListaLeitura.DoesNotExist:
                return Response({"erro": "Lista de Leitura não encontrada."},
                                status=status.HTTP_404_NOT_FOUND)

            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

            serializer = LivrosListasLeituraSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Livro adicionado à lista com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        if request.method == 'PUT':
            if id_lista is None or id_livro is None:
                return Response({"erro": "IDs 'id_lista' e 'id_livro' são obrigatórios na URL."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                registro = LivrosListasLeitura.objects.get(id_lista=id_lista, id_livro=id_livro)
            except LivrosListasLeitura.DoesNotExist:
                return Response({"erro": "Registro não encontrado."},
                                status=status.HTTP_404_NOT_FOUND)

            lista = ListaLeitura.objects.get(id=id_lista)
            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

            serializer = LivrosListasLeituraSerializer(registro, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Registro atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        if request.method == 'DELETE':
            if id_lista is None or id_livro is None:
                return Response({"erro": "IDs 'id_lista' e 'id_livro' são obrigatórios na URL."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                registro = LivrosListasLeitura.objects.get(id_lista=id_lista, id_livro=id_livro)
            except LivrosListasLeitura.DoesNotExist:
                return Response({"erro": "Registro não encontrado."},
                                status=status.HTTP_404_NOT_FOUND)

            lista = ListaLeitura.objects.get(id=id_lista)
            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

            registro.delete()
            return Response({"mensagem": "Livro removido da lista com sucesso."},
                            status=status.HTTP_204_NO_CONTENT)

    except Exception as e:
        return Response({
            "erro": "Erro interno no servidor.",
            "detalhes": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar recursos digitais de listas de leitura ou buscar um recurso específico",
        description=(
            "Usuários comuns podem listar e acessar apenas recursos digitais em suas próprias listas de leitura. "
            "Administradores podem listar e acessar todos os recursos digitais de todas as listas."
        ),
        tags=["Recursos Digitais em Listas de Leitura"],
        responses={
            200: OpenApiResponse(description="Recurso(s) listado(s) com sucesso"),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Registro não encontrado"),
        }
    ),
    post=extend_schema(
        summary="Adicionar recurso digital a uma lista de leitura",
        description="Usuários comuns podem adicionar recursos às próprias listas. Administradores podem adicionar em qualquer lista.",
        request=RecursosDigitaisListasLeituraSerializer,
        tags=["Recursos Digitais em Listas de Leitura"],
        responses={
            201: OpenApiResponse(description="Recurso adicionado com sucesso"),
            400: OpenApiResponse(description="Dados inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um recurso digital em uma lista",
        description="Usuários comuns podem atualizar apenas recursos nas próprias listas. Administradores podem atualizar qualquer lista.",
        request=RecursosDigitaisListasLeituraSerializer,
        parameters=[
            OpenApiParameter(name='id_lista', required=True, type=int, location=OpenApiParameter.PATH),
            OpenApiParameter(name='id_recurso_digital', required=True, type=int, location=OpenApiParameter.PATH),
        ],
        tags=["Recursos Digitais em Listas de Leitura"],
        responses={
            200: OpenApiResponse(description="Registro atualizado com sucesso"),
            400: OpenApiResponse(description="Dados inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Registro não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Remover um recurso digital de uma lista",
        description="Usuários comuns podem remover recursos apenas de suas próprias listas. Administradores podem remover de qualquer lista.",
        parameters=[
            OpenApiParameter(name='id_lista', required=True, type=int, location=OpenApiParameter.PATH),
            OpenApiParameter(name='id_recurso_digital', required=True, type=int, location=OpenApiParameter.PATH),
        ],
        tags=["Recursos Digitais em Listas de Leitura"],
        responses={
            204: OpenApiResponse(description="Recurso removido da lista com sucesso"),
            400: OpenApiResponse(description="IDs inválidos"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada"),
            404: OpenApiResponse(description="Registro não encontrado"),
        }
    )
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def recursos_digitais_listas_leitura_manager(request, id_lista=None, id_recurso_digital=None):
    user = request.user
    is_admin = user.tipo == 'administrador'

    try:
        if id_lista is not None:
            id_lista = int(id_lista)
        if id_recurso_digital is not None:
            id_recurso_digital = int(id_recurso_digital)

        if request.method == 'GET':
            if id_lista and id_recurso_digital:
                try:
                    registro = RecursosDigitaisListasLeitura.objects.get(
                        id_lista=id_lista, id_recurso_digital=id_recurso_digital
                    )
                    lista = ListaLeitura.objects.get(id=id_lista)

                    if not is_admin and lista.id_usuario != user.id:
                        return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)

                    serializer = RecursosDigitaisListasLeituraSerializer(registro)
                    return Response(serializer.data, status=status.HTTP_200_OK)

                except RecursosDigitaisListasLeitura.DoesNotExist:
                    return Response({"erro": "Registro não encontrado."}, status=status.HTTP_404_NOT_FOUND)

            elif id_lista:
                lista = ListaLeitura.objects.get(id=id_lista)
                if not is_admin and lista.id_usuario != user.id:
                    return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)

                registros = RecursosDigitaisListasLeitura.objects.filter(id_lista=id_lista)
                serializer = RecursosDigitaisListasLeituraSerializer(registros, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:
                if is_admin:
                    registros = RecursosDigitaisListasLeitura.objects.all()
                else:
                    listas_ids = ListaLeitura.objects.filter(id_usuario=user.id).values_list('id', flat=True)
                    registros = RecursosDigitaisListasLeitura.objects.filter(id_lista__in=listas_ids)

                serializer = RecursosDigitaisListasLeituraSerializer(registros, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        if request.method == 'POST':
            data = request.data.copy()

            id_lista = int(data.get('id_lista'))
            id_recurso = int(data.get('id_recurso_digital'))

            try:
                lista = ListaLeitura.objects.get(id=id_lista)
            except ListaLeitura.DoesNotExist:
                return Response({"erro": "Lista de Leitura não encontrada."}, status=status.HTTP_404_NOT_FOUND)

            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)

            serializer = RecursosDigitaisListasLeituraSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Recurso digital adicionado à lista com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        if request.method == 'PUT':
            if id_lista is None or id_recurso_digital is None:
                return Response({"erro": "IDs 'id_lista' e 'id_recurso_digital' são obrigatórios na URL."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                registro = RecursosDigitaisListasLeitura.objects.get(
                    id_lista=id_lista, id_recurso_digital=id_recurso_digital
                )
            except RecursosDigitaisListasLeitura.DoesNotExist:
                return Response({"erro": "Registro não encontrado."}, status=status.HTTP_404_NOT_FOUND)

            lista = ListaLeitura.objects.get(id=id_lista)
            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

            serializer = RecursosDigitaisListasLeituraSerializer(registro, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Registro atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)

            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors},
                            status=status.HTTP_400_BAD_REQUEST)

        if request.method == 'DELETE':
            if id_lista is None or id_recurso_digital is None:
                return Response({"erro": "IDs 'id_lista' e 'id_recurso_digital' são obrigatórios na URL."},
                                status=status.HTTP_400_BAD_REQUEST)

            try:
                registro = RecursosDigitaisListasLeitura.objects.get(
                    id_lista=id_lista, id_recurso_digital=id_recurso_digital
                )
            except RecursosDigitaisListasLeitura.DoesNotExist:
                return Response({"erro": "Registro não encontrado."},
                                status=status.HTTP_404_NOT_FOUND)

            lista = ListaLeitura.objects.get(id=id_lista)
            if not is_admin and lista.id_usuario != user.id:
                return Response({"erro": "Acesso negado. Esta lista não pertence a você."},
                                status=status.HTTP_403_FORBIDDEN)

            registro.delete()
            return Response({"mensagem": "Recurso digital removido da lista com sucesso."},
                            status=status.HTTP_204_NO_CONTENT)

    except ListaLeitura.DoesNotExist:
        return Response({"erro": "Lista de Leitura não encontrada."},
                        status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({
            "erro": "Erro interno no servidor.",
            "detalhes": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar histórico de empréstimos",
        description=(
            "Administradores podem listar todos os históricos ou um específico. "
            "Usuários comuns podem listar ou acessar apenas seus próprios históricos."
        ),
        parameters=[],
        tags=["Histórico de Empréstimos"],
        responses={
            200: HistoricoEmprestimoSerializer(many=True),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Histórico de empréstimo não encontrado"),
        },
    ),
    post=extend_schema(
        summary="Registrar um novo histórico de empréstimo",
        description=(
            "Apenas o sistema e administradores podem criar novos históricos. "
            "Campos obrigatórios: `id_usuario`, `id_exemplar`, `data_emprestimo` e `data_devolucao_prevista`."
        ),
        request=HistoricoEmprestimoSerializer,
        tags=["Histórico de Empréstimos"],
        responses={
            201: OpenApiResponse(description="Histórico de empréstimo criado com sucesso", response=HistoricoEmprestimoSerializer),
            400: OpenApiResponse(description="Dados inválidos ou campos obrigatórios ausentes"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada para registrar empréstimos"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um histórico de empréstimo existente",
        description=(
            "Apenas administradores podem atualizar históricos. "
            "O ID do histórico é obrigatório na URL."
        ),
        parameters=[
            OpenApiParameter(
                name='id', required=True, type=int, location=OpenApiParameter.PATH,
                description="ID do histórico de empréstimo a ser atualizado"
            )
        ],
        tags=["Histórico de Empréstimos"],
        request=HistoricoEmprestimoSerializer,
        responses={
            200: OpenApiResponse(description="Histórico atualizado com sucesso", response=HistoricoEmprestimoSerializer),
            400: OpenApiResponse(description="Dados inválidos ou ID ausente"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada para atualizar empréstimos"),
            404: OpenApiResponse(description="Histórico não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Excluir um histórico de empréstimo",
        description=(
            "Apenas administradores podem excluir históricos. "
            "O ID do histórico é obrigatório na URL."
        ),
        parameters=[
            OpenApiParameter(
                name='id', required=True, type=int, location=OpenApiParameter.PATH,
                description="ID do histórico de empréstimo a ser excluído"
            )
        ],
        tags=["Histórico de Empréstimos"],
        responses={
            204: OpenApiResponse(description="Histórico deletado com sucesso"),
            400: OpenApiResponse(description="ID ausente ou inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada para excluir empréstimos"),
            404: OpenApiResponse(description="Histórico não encontrado"),
        },
    ),
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def historico_emprestimo_manager(request, id=None):
    try:
        if request.method == 'GET':
            if id:
                historico = HistoricoEmprestimo.objects.get(id=id)
                if request.user.tipo != 'administrador' and historico.id_usuario.id != request.user.id:
                    return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)
                serializer = HistoricoEmprestimoSerializer(historico)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                if request.user.tipo == 'administrador':
                    historicos = HistoricoEmprestimo.objects.all()
                else:
                    historicos = HistoricoEmprestimo.objects.filter(id_usuario=request.user.id)
                serializer = HistoricoEmprestimoSerializer(historicos, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem registrar empréstimos."}, status=status.HTTP_403_FORBIDDEN)

            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            campos_obrigatorios = ['id_usuario', 'id_exemplar', 'data_emprestimo', 'data_devolucao_prevista']
            for campo in campos_obrigatorios:
                if campo not in request.data or not str(request.data[campo]).strip():
                    return Response({"erro": f"O campo '{campo}' é obrigatório e não pode estar vazio."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = HistoricoEmprestimoSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Histórico de empréstimo adicionado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem atualizar empréstimos."}, status=status.HTTP_403_FORBIDDEN)
            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            historico = HistoricoEmprestimo.objects.get(id=id)

            if not request.data:
                return Response({"erro": "Dados não fornecidos para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            serializer = HistoricoEmprestimoSerializer(historico, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Histórico de empréstimo atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem excluir empréstimos."}, status=status.HTTP_403_FORBIDDEN)
            if not id:
                return Response({"erro": "ID é obrigatório para exclusão."}, status=status.HTTP_400_BAD_REQUEST)

            historico = HistoricoEmprestimo.objects.get(id=id)
            historico.delete()
            return Response({"mensagem": "Histórico de empréstimo deletado com sucesso."}, status=status.HTTP_204_NO_CONTENT)

    except HistoricoEmprestimo.DoesNotExist:
        return Response({"erro": "Histórico de empréstimo não encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar favoritos ou buscar favorito por ID",
        description=(
            "Administradores podem listar todos os favoritos ou um específico. "
            "Usuários comuns podem listar ou acessar apenas seus próprios favoritos."
        ),
        tags=["Favoritos"],
        responses={
            200: FavoritoSerializer(many=True),
            400: OpenApiResponse(description="ID inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Acesso negado"),
            404: OpenApiResponse(description="Favorito não encontrado"),
        },
    ),
    post=extend_schema(
        summary="Adicionar um novo favorito",
        description=(
            "Qualquer usuário autenticado pode adicionar um favorito.\n\n"
            "- O campo `id_usuario` é preenchido automaticamente com o usuário autenticado.\n"
            "- Você deve informar **apenas um** dos campos: `id_livro` **ou** `id_recurso_digital`.\n"
            "- **Não informe os dois ao mesmo tempo.**"
        ),
        request=FavoritoSerializer,
        tags=["Favoritos"],
        responses={
            201: OpenApiResponse(description="Favorito criado com sucesso", response=FavoritoSerializer),
            400: OpenApiResponse(description="Dados inválidos ou campos obrigatórios ausentes"),
            401: OpenApiResponse(description="Não autenticado"),
        }
    ),
    put=extend_schema(
        summary="Atualizar um favorito existente",
        description=(
            "Apenas administradores podem atualizar favoritos. "
            "O ID do favorito é obrigatório na URL."
        ),
        parameters=[
            OpenApiParameter(
                name='id', required=True, type=int, location=OpenApiParameter.PATH,
                description="ID do favorito a ser atualizado"
            )
        ],
        tags=["Favoritos"],
        request=FavoritoSerializer,
        responses={
            200: OpenApiResponse(description="Favorito atualizado com sucesso", response=FavoritoSerializer),
            400: OpenApiResponse(description="Dados inválidos ou ID ausente"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada para atualizar favoritos"),
            404: OpenApiResponse(description="Favorito não encontrado"),
        }
    ),
    delete=extend_schema(
        summary="Excluir um favorito",
        description=(
            "Administradores podem excluir qualquer favorito. "
            "Usuários comuns só podem excluir seus próprios favoritos. "
            "O ID do favorito é obrigatório na URL."
        ),
        parameters=[
            OpenApiParameter(
                name='id', required=True, type=int, location=OpenApiParameter.PATH,
                description="ID do favorito a ser excluído"
            )
        ],
        tags=["Favoritos"],
        responses={
            200: OpenApiResponse(description="Favorito deletado com sucesso"),
            400: OpenApiResponse(description="ID ausente ou inválido"),
            401: OpenApiResponse(description="Não autenticado"),
            403: OpenApiResponse(description="Permissão negada para excluir favorito"),
            404: OpenApiResponse(description="Favorito não encontrado"),
        }
    ),
)
@api_view(['GET', 'POST', 'PUT', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def favorito_manager(request, id=None):
    try:
        if request.method == 'GET':
            if id:
                favorito = Favorito.objects.get(id=id)
                if request.user.tipo != 'administrador' and favorito.id_usuario.id != request.user.id:
                    return Response({"erro": "Acesso negado."}, status=status.HTTP_403_FORBIDDEN)
                serializer = FavoritoSerializer(favorito)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                if request.user.tipo == 'administrador':
                    favoritos = Favorito.objects.all()
                else:
                    favoritos = Favorito.objects.filter(id_usuario=request.user.id)
                serializer = FavoritoSerializer(favoritos, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

        elif request.method == 'POST':
            if not request.data:
                return Response({"erro": "Dados não fornecidos."}, status=status.HTTP_400_BAD_REQUEST)

            data = request.data.copy()
            data['id_usuario'] = request.user.id

            id_livro = data.get('id_livro')
            id_recurso = data.get('id_recurso_digital')

            if not id_livro and not id_recurso:
                return Response(
                    {"erro": "É obrigatório informar 'id_livro' ou 'id_recurso_digital'."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if id_livro and id_recurso:
                return Response(
                    {"erro": "Informe apenas um dos campos: 'id_livro' ou 'id_recurso_digital', não ambos."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = FavoritoSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Favorito adicionado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'PUT':
            if request.user.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem atualizar favoritos."}, status=status.HTTP_403_FORBIDDEN)
            if not id:
                return Response({"erro": "ID é obrigatório para atualização."}, status=status.HTTP_400_BAD_REQUEST)

            favorito = Favorito.objects.get(id=id)
            data = request.data.copy()

            campos_obrigatorios = ['tipo_conteudo', 'id_conteudo', 'id_usuario']
            for campo in campos_obrigatorios:
                valor = str(data.get(campo, '')).strip()
                if not valor:
                    return Response(
                        {"erro": f"O campo '{campo}' é obrigatório e não pode estar vazio."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                data[campo] = valor 

            serializer = FavoritoSerializer(favorito, data=data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Favorito atualizado com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_200_OK)
            return Response({"erro": "Dados inválidos.", "detalhes": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        elif request.method == 'DELETE':
            if not id:
                return Response({"erro": "ID é obrigatório para exclusão."}, status=status.HTTP_400_BAD_REQUEST)

            favorito = Favorito.objects.get(id=id)

            if request.user.tipo != 'administrador' and favorito.id_usuario.id != request.user.id:
                return Response({"erro": "Você não tem permissão para excluir este favorito."}, status=status.HTTP_403_FORBIDDEN)

            favorito.delete()
            return Response({"mensagem": "Favorito deletado com sucesso."}, status=status.HTTP_200_OK)

    except Favorito.DoesNotExist:
        return Response({"erro": "Favorito não encontrado."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"erro": "Erro interno do servidor.", "detalhes": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Listar notificações",
        description=(
            "Retorna uma lista de notificações para o usuário autenticado.\n\n"
            "- Usuários comuns recebem **apenas as próprias notificações**.\n"
            "- Administradores podem listar todas ou filtrar por `id_usuario` via query param."
        ),
        parameters=[],
        responses={
            200: OpenApiResponse(
                description="Lista de notificações retornada com sucesso.",
                response=NotificacaoSerializer(many=True)
            ),
            400: OpenApiResponse(description="Parâmetro inválido."),
            401: OpenApiResponse(description="Usuário não autenticado."),
            403: OpenApiResponse(description="Acesso negado."),
            404: OpenApiResponse(description="Usuário não encontrado."),
            500: OpenApiResponse(description="Erro interno ao buscar notificações."),
        },
        tags=["Notificações"]
    ),
    post=extend_schema(
        summary="Enviar notificação",
        description=(
            "Cria uma nova notificação para um usuário. **Apenas administradores** têm permissão para isso.\n\n"
            "Campos esperados no corpo da requisição:\n"
            "- `usuario`: ID do usuário que deve receber a notificação.\n"
            "- `mensagem`: Texto da notificação."
        ),
        request=NotificacaoSerializer,
        responses={
            201: OpenApiResponse(
                description="Notificação criada com sucesso.",
                response=NotificacaoSerializer
            ),
            400: OpenApiResponse(description="Dados inválidos."),
            401: OpenApiResponse(description="Usuário não autenticado."),
            403: OpenApiResponse(description="Apenas administradores podem criar notificações."),
            500: OpenApiResponse(description="Erro interno ao criar notificação."),
        },
        tags=["Notificações"]
    ),
    put=extend_schema(
        summary="Atualizar uma notificação (marcar como lida ou editar mensagem)",
        description=(
            "- **Usuários comuns** podem **marcar como lida** apenas **suas próprias notificações**.\n"
            "- **Administradores** podem além de marcar como lida, também **editar o conteúdo da mensagem** e alterar o campo `usuario` se desejado.\n\n"
        ),
        request={
            "application/json": {
                "type": "object",
                "properties": {
                    "lida": {
                        "type": "boolean",
                        "description": "Marcar a notificação como lida ou não."
                    }
                },
                "required": ["lida"]
            }
        },
        parameters=[
            OpenApiParameter(
                name='id',
                required=True,
                type=int,
                location=OpenApiParameter.PATH,
                description="ID da notificação a ser atualizada."
            )
        ],
        responses={
            200: OpenApiResponse(description="Notificação atualizada com sucesso."),
            400: OpenApiResponse(description="Dados inválidos ou campos ausentes."),
            401: OpenApiResponse(description="Não autenticado."),
            403: OpenApiResponse(description="Acesso negado. Você não tem permissão para editar esta notificação."),
            404: OpenApiResponse(description="Notificação não encontrada."),
            500: OpenApiResponse(description="Erro interno ao atualizar a notificação."),
        },
        tags=["Notificações"]
)
)
@api_view(['GET', 'POST', 'PUT'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def notificacoes_manager(request, id=None):
    usuario = request.user

    if request.method == 'GET':
        try:
            if usuario.tipo == 'administrador':
                id_usuario = request.query_params.get('id_usuario')
                if id_usuario:
                    if not str(id_usuario).isdigit():
                        return Response(
                            {"erro": "O parâmetro 'id_usuario' deve ser um número inteiro válido."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    id_usuario_int = int(id_usuario)
                    if not Usuario.objects.filter(id=id_usuario_int).exists():
                        return Response({"erro": "Usuário não encontrado."}, status=status.HTTP_404_NOT_FOUND)

                    notificacoes = Notificacao.objects.filter(usuario_id=id_usuario_int)
                else:
                    notificacoes = Notificacao.objects.all()
            else:
                notificacoes = Notificacao.objects.filter(usuario=usuario)

            notificacoes = notificacoes.order_by('-data_criacao')
            serializer = NotificacaoSerializer(notificacoes, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                "erro": "Erro ao buscar notificações.",
                "detalhes": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'POST':
        if usuario.tipo != 'administrador':
            return Response({"erro": "Apenas administradores podem criar notificações."}, status=status.HTTP_403_FORBIDDEN)

        try:
            serializer = NotificacaoSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({
                    "mensagem": "Notificação criada com sucesso.",
                    "dados": serializer.data
                }, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "erro": "Erro ao criar notificação.",
                "detalhes": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    elif request.method == 'PUT':
        if id is None:
            return Response({"erro": "ID da notificação é obrigatório na URL."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            notificacao = Notificacao.objects.get(id=id)
        except Notificacao.DoesNotExist:
            return Response({"erro": "Notificação não encontrada."}, status=status.HTTP_404_NOT_FOUND)

        if usuario.tipo != 'administrador' and notificacao.usuario != usuario:
            return Response({"erro": "Você não tem permissão para editar esta notificação."}, status=status.HTTP_403_FORBIDDEN)

        lida = request.data.get('lida', None)
        mensagem = request.data.get('mensagem', None)

        if lida is None:
            return Response({"erro": "Campo 'lida' é obrigatório."}, status=status.HTTP_400_BAD_REQUEST)

        if not isinstance(lida, bool):
            return Response({"erro": "Campo 'lida' deve ser booleano."}, status=status.HTTP_400_BAD_REQUEST)

        notificacao.lida = lida

        if mensagem is not None:
            if usuario.tipo != 'administrador':
                return Response({"erro": "Apenas administradores podem editar o conteúdo da mensagem."}, status=status.HTTP_403_FORBIDDEN)
            notificacao.mensagem = mensagem

        notificacao.save()

        return Response({"mensagem": "Notificação atualizada com sucesso."}, status=status.HTTP_200_OK)
    

@extend_schema(
    methods=["GET"],
    summary="Busca avançada no acervo",
    description="Permite filtrar livros e recursos digitais por título, autor, ano, gênero, quantidade de páginas e outros parâmetros.",
    parameters=[
        OpenApiParameter(name="titulo", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                         description="Filtrar pelo título."),
        OpenApiParameter(name="autor", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                         description="Filtrar pelo autor (ou descrição, no caso de recursos digitais)."),
        OpenApiParameter(name="editora", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                         description="Filtrar pela editora (ou descrição, no caso de recursos digitais)."),
        OpenApiParameter(name="ano_publicacao", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                         description="Filtrar pelo ano de publicação (livros) ou ano de disponibilidade (recursos digitais)."),
        OpenApiParameter(name="qtd_paginas_min", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                         description="Quantidade mínima de páginas."),
        OpenApiParameter(name="qtd_paginas_max", type=OpenApiTypes.INT, location=OpenApiParameter.QUERY,
                         description="Quantidade máxima de páginas."),
        OpenApiParameter(name="generos", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                         description="Filtrar por gêneros (separados por vírgula, ex.: Ficção,Aventura)."),
        OpenApiParameter(name="tipo", type=OpenApiTypes.STR, location=OpenApiParameter.QUERY,
                         description="Filtrar pelo tipo: 'livro', 'recurso' ou omitir para ambos."),
    ],
    tags=['Busca Avançada no Acervo'],
    responses={
        200: OpenApiResponse(
            description="Busca realizada com sucesso. Retorna a lista de livros e/ou recursos digitais encontrados."
        ),
        400: OpenApiResponse(
            description="Requisição inválida. Algum parâmetro enviado está incorreto (ex.: ano ou quantidade de páginas não numéricos)."
        ),
        401: OpenApiResponse(
            description="Usuário não autenticado. É necessário fornecer um token JWT válido."
        ),
        403: OpenApiResponse(
            description="Acesso negado. O usuário não possui permissão para acessar este recurso."
        ),
        404: OpenApiResponse(
            description="Nenhum livro ou recurso digital encontrado com os critérios fornecidos."
        ),
        500: OpenApiResponse(
            description="Erro interno ao realizar a busca avançada."
        ),
    }
)
@api_view(["GET"])
def busca_avancada(request):
    try:
        titulo = request.GET.get('titulo')
        autor = request.GET.get('autor')
        editora = request.GET.get('editora')
        ano_publicacao = request.GET.get('ano_publicacao')
        qtd_paginas_min = request.GET.get('qtd_paginas_min')
        qtd_paginas_max = request.GET.get('qtd_paginas_max')
        generos = request.GET.get('generos')
        tipo = request.GET.get('tipo')

        try:
            ano_int = int(ano_publicacao) if ano_publicacao else None
            qtd_min_int = int(qtd_paginas_min) if qtd_paginas_min else None
            qtd_max_int = int(qtd_paginas_max) if qtd_paginas_max else None
            generos = [g.strip() for g in generos.split(',')] if generos else []
        except ValueError:
            return Response({"erro": "Parâmetros numéricos inválidos."}, status=status.HTTP_400_BAD_REQUEST)

        livros_resultado = []
        recursos_resultado = []

        if not tipo or tipo == 'livro':
            filtros_livro = Q()
            if titulo:
                filtros_livro &= Q(titulo__icontains=titulo)
            if autor:
                filtros_livro &= Q(autor__icontains=autor)
            if editora:
                filtros_livro &= Q(editora__icontains=editora)
            if ano_int:
                filtros_livro &= Q(ano_publicacao=ano_int)
            if qtd_min_int is not None:
                filtros_livro &= Q(numero_paginas__gte=qtd_min_int)
            if qtd_max_int is not None:
                filtros_livro &= Q(numero_paginas__lte=qtd_max_int)
            if generos:
                filtros_livro &= Q(genero__in=generos)

            livros = Livro.objects.filter(filtros_livro)
            livros_resultado = LivroSerializer(livros, many=True).data

        if not tipo or tipo == 'recurso':
            filtros_recurso = Q()
            if titulo:
                filtros_recurso &= Q(titulo__icontains=titulo)
            if autor:
                filtros_recurso &= Q(descricao__icontains=autor)
            if editora:
                filtros_recurso &= Q(descricao__icontains=editora)
            if ano_int:
                filtros_recurso &= Q(data_disponibilidade__year=ano_int)
            if qtd_min_int is not None:
                filtros_recurso &= Q(numero_paginas__gte=qtd_min_int)
            if qtd_max_int is not None:
                filtros_recurso &= Q(numero_paginas__lte=qtd_max_int)
            if generos:
                filtros_recurso &= Q(genero__in=generos)

            recursos = RecursoDigital.objects.filter(filtros_recurso)
            recursos_resultado = RecursoDigitalSerializer(recursos, many=True).data

        return Response({
            "livros": livros_resultado,
            "recursos_digitais": recursos_resultado
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            "erro": "Erro interno ao realizar a busca avançada.",
            "detalhes": str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Relatório de uso do acervo da biblioteca (PDF)",
        description=(
            "Gera um relatório consolidado em PDF com estatísticas de uso do acervo da biblioteca, "
            "incluindo livros mais emprestados, recursos digitais mais acessados, total de empréstimos, "
            "estoque atual, obras com maior tempo fora da biblioteca, favoritos e devoluções em atraso.\n\n"
            "**Apenas administradores podem acessar este relatório.**"
        ),
        responses={
            (200, 'application/pdf'): OpenApiResponse(description="Relatório PDF gerado com sucesso."),
            403: OpenApiResponse(description="Acesso negado. Apenas administradores podem gerar relatórios."),
            500: OpenApiResponse(description="Erro interno na geração do relatório."),
        },
        tags=['Relatórios']
    )
)
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def gerar_relatorio_pdf(request):
    if request.user.tipo != 'administrador':
        return Response({'erro': 'Apenas administradores podem gerar este relatório'}, status=status.HTTP_403_FORBIDDEN)

    try:
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        width, height = A4
        y = height - 50

        p.setFont("Helvetica-Bold", 16)
        p.drawString(50, y, "Relatório de Uso do Acervo da Biblioteca")
        y -= 30
        p.setFont("Helvetica", 12)
        p.drawString(50, y, f"Gerado por: {getattr(request.user, 'nome', 'Desconhecido')}")
        y -= 30

        def titulo(sec):
            nonlocal y
            y -= 20
            if y < 100:
                p.showPage()
                y = height - 50
            p.setFont("Helvetica-Bold", 13)
            p.drawString(50, y, sec)
            y -= 20
            p.setFont("Helvetica", 11)

        def linha(txt):
            nonlocal y
            if y < 50:
                p.showPage()
                y = height - 50
            p.drawString(60, y, txt)
            y -= 15

        from django.db import connection

        def executar_sql(query):
            with connection.cursor() as cursor:
                cursor.execute(query)
                colunas = [col[0] for col in cursor.description]
                resultados = [dict(zip(colunas, row)) for row in cursor.fetchall()]
            return resultados

        titulo("1. Estoque de livros por gênero")
        consulta_estoque = """
            SELECT l.genero, SUM(l.quantidade_disponivel) AS total_disponivel
            FROM Livros l
            GROUP BY l.genero
            ORDER BY total_disponivel DESC;
        """
        estoque_por_genero = executar_sql(consulta_estoque)
        if estoque_por_genero:
            for item in estoque_por_genero:
                linha(f"Gênero: {item['genero']} - Disponíveis: {item['total_disponivel']}")
        else:
            linha("Nenhum dado disponível.")

        titulo("2. Top 5 livros mais emprestados")
        consulta_livros_emprestados = """
            SELECT l.titulo, COUNT(e.id) AS numero_emprestimos
            FROM Livros l
            INNER JOIN Exemplares ex ON l.id = ex.id_livro
            INNER JOIN Emprestimos e ON ex.id = e.id_exemplar
            GROUP BY l.titulo
            ORDER BY numero_emprestimos DESC
            LIMIT 5;
        """
        livros_emprestados = executar_sql(consulta_livros_emprestados)
        if livros_emprestados:
            for item in livros_emprestados:
                linha(f"{item['titulo']} ({item['numero_emprestimos']} empréstimos)")
        else:
            linha("Nenhum dado disponível.")

        titulo("3. Livros mais favoritados")
        consulta_favoritos = """
            SELECT l.titulo, COUNT(f.id_usuario) AS numero_favoritos
            FROM Favoritos f
            RIGHT JOIN Livros l ON f.id_livro = l.id
            GROUP BY l.titulo
            ORDER BY numero_favoritos DESC;
        """
        livros_favoritados = executar_sql(consulta_favoritos)
        if livros_favoritados:
            for item in livros_favoritados:
                linha(f"{item['titulo']} ({item['numero_favoritos']} favoritos)")
        else:
            linha("Nenhum dado disponível.")

        titulo("4. Livros físicos disponíveis")
        livros_disponiveis = executar_sql("SELECT * FROM vw_livros_disponiveis;")
        if livros_disponiveis:
            for item in livros_disponiveis:
                linha(f"{item['titulo']} - {item['autor']} ({item['numero_paginas']} páginas)")
        else:
            linha("Nenhum dado disponível.")

        titulo("5. Usuários com empréstimos pendentes ou ativos")
        usuarios_ativos = executar_sql("SELECT * FROM vw_usuarios_com_emprestimos;")
        if usuarios_ativos:
            for item in usuarios_ativos:
                linha(f"{item['nome']} - {item['numero_emprestimos']} empréstimos ativos")
        else:
            linha("Nenhum dado disponível.")

        titulo("6. Total de empréstimos registrados")
        total_emprestimos = Emprestimo.objects.count()
        linha(f"Total: {total_emprestimos}")

        titulo("7. Estoque atual de exemplares disponíveis")
        estoque_atual = Exemplar.objects.filter(status='disponivel').count()
        linha(f"Exemplares disponíveis: {estoque_atual}")

        titulo("8. Obras com maior tempo fora da biblioteca")
        tempo_fora = Emprestimo.objects.exclude(data_devolucao_real=None).annotate(
            tempo=ExpressionWrapper(
                F('data_devolucao_real') - F('data_emprestimo'),
                output_field=DurationField()
            )
        ).order_by('-tempo')[:5]
        if tempo_fora:
            for e in tempo_fora:
                exemplar = Exemplar.objects.filter(id=e.id_exemplar).select_related('id_livro').first()
                livro = exemplar.id_livro if exemplar else None
                usuario = Usuario.objects.filter(id=e.id_usuario).first()
                nome_usuario = usuario.nome if usuario else "Desconhecido"
                if livro:
                    linha(f"{livro.titulo} - {nome_usuario} ({e.tempo})")
        else:
            linha("Nenhum dado disponível.")

        titulo("9. Estatísticas de devoluções em atraso")
        atrasos = Emprestimo.objects.filter(
            data_devolucao_real__gt=F('data_devolucao_prevista')
        ).count()
        linha(f"Devoluções em atraso: {atrasos}")

        p.showPage()
        p.save()
        buffer.seek(0)
        return HttpResponse(buffer, content_type='application/pdf')

    except Exception as e:
        return Response(
            {"erro": "Erro ao gerar o relatório em PDF", "detalhes": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
