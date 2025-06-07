from rest_framework import serializers
from .models import Livro, Exemplar, Usuario, Emprestimo, Reserva, RecursoDigital, ListaLeitura, LivrosListasLeitura, RecursosDigitaisListasLeitura, HistoricoEmprestimo, Favorito
from rest_framework import serializers
from .models import Usuario
from django.contrib.auth.hashers import make_password
from app.models import Notificacao

class LivroSerializer(serializers.ModelSerializer):
    class Meta:
        model = Livro
        fields = '__all__'

class ExemplarSerializer(serializers.ModelSerializer):
    class Meta:
        model = Exemplar
        fields = '__all__'

class ErroSerializer(serializers.Serializer):
    erro = serializers.CharField()
    detalhes = serializers.CharField(required=False)

class UsuarioSerializer(serializers.ModelSerializer):
    class Meta:
        model = Usuario
        fields = '__all__'

class UsuarioLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

class UsuarioInfoSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    nome = serializers.CharField()
    email = serializers.EmailField()
    tipo = serializers.CharField()

class UsuarioInfoSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    nome = serializers.CharField()
    email = serializers.EmailField()
    tipo = serializers.CharField()

class UsuarioLoginResponseSerializer(serializers.Serializer):
    mensagem = serializers.CharField()
    refresh = serializers.CharField()
    access = serializers.CharField()
    usuario = UsuarioInfoSerializer()


class UsuarioSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Usuario
        fields = ['id', 'nome', 'tipo', 'email', 'telefone', 'password', 'punido_ate']
        extra_kwargs = {
            'password': {'write_only': True},
            'punido_ate': {'required': False}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        if password:
            validated_data['password'] = make_password(password)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        if password:
            instance.set_password(password)
        return super().update(instance, validated_data)


class EmprestimoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Emprestimo
        fields = '__all__'

class ReservaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reserva
        fields = '__all__'

    def validate(self, data):
        request = self.context['request']
        usuario = request.user

        if usuario.tipo != 'administrador':
            data['id_usuario'] = usuario.id
        else:
            if not data.get('id_usuario'):
                raise serializers.ValidationError("ID do usuário é obrigatório.")

        id_exemplar = data.get('id_exemplar')
        if id_exemplar:
            try:
                exemplar = Exemplar.objects.get(id=id_exemplar)
            except Exemplar.DoesNotExist:
                raise serializers.ValidationError("Exemplar não encontrado.")

            if exemplar.status == 'disponivel':
                raise serializers.ValidationError("O exemplar está disponível. Não é necessário reservar. Faça o empréstimo diretamente.")


        return data

    def create(self, validated_data):
        reserva = super().create(validated_data)

        reserva.status = 'pendente'
        reserva.save()

        return reserva


class RecursoDigitalSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecursoDigital
        fields = '__all__'

class ListaLeituraSerializer(serializers.ModelSerializer):
    class Meta:
        model = ListaLeitura
        fields = '__all__'

class LivrosListasLeituraSerializer(serializers.ModelSerializer):
    class Meta:
        model = LivrosListasLeitura
        fields = '__all__'

class RecursosDigitaisListasLeituraSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecursosDigitaisListasLeitura
        fields = '__all__'

class HistoricoEmprestimoSerializer(serializers.ModelSerializer):
    class Meta:
        model = HistoricoEmprestimo
        fields = '__all__'

class FavoritoSerializer(serializers.ModelSerializer):

    usuario = serializers.StringRelatedField(source='id_usuario', read_only=True)
    livro = serializers.StringRelatedField(source='id_livro', read_only=True)
    recurso_digital = serializers.StringRelatedField(source='id_recurso_digital', read_only=True)

    id_usuario = serializers.PrimaryKeyRelatedField(queryset=Usuario.objects.all())
    id_livro = serializers.PrimaryKeyRelatedField(queryset=Livro.objects.all(), allow_null=True, required=False)
    id_recurso_digital = serializers.PrimaryKeyRelatedField(queryset=RecursoDigital.objects.all(), allow_null=True, required=False)

    class Meta:
        model = Favorito
        fields = [
            'id',
            'id_usuario',
            'usuario',
            'id_livro',
            'livro',
            'id_recurso_digital',
            'recurso_digital',
            'data_favoritado'
        ]
        read_only_fields = ['id', 'data_favoritado']

class NotificacaoSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notificacao
        fields = '__all__'

    