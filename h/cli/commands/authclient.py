import click

from h import models
from h.models.auth_client import GrantType, ResponseType
from h.security import token_urlsafe


@click.group()
def authclient():
    """Manage OAuth clients."""


@authclient.command()
@click.option("--name", prompt=True, help="The name of the client")
@click.option(
    "--authority",
    prompt=True,
    help="The authority (domain name) of the resources managed by the client",
)
@click.option(
    "--type",
    "type_",
    type=click.Choice(["public", "confidential"]),
    prompt=True,
    help="The OAuth client type (public, or confidential)",
)
@click.option(
    "--redirect-uri",
    prompt=False,
    help="URI for browser redirect after authorization. Required if grant type is 'authorization_code'",
)
@click.option(
    "--grant-type",
    type=click.Choice(list(GrantType.__members__)),
    prompt=False,
    help="An allowable grant type",
)
@click.pass_context
def add(ctx, name, authority, type_, redirect_uri, grant_type):  # noqa: PLR0913
    """Create a new OAuth client."""
    request = ctx.obj["bootstrap"]()

    client = models.AuthClient(name=name, authority=authority)
    if type_ == "confidential":
        client.secret = token_urlsafe()
    client.redirect_uri = redirect_uri
    client.grant_type = grant_type
    request.db.add(client)
    request.db.flush()

    id_ = client.id
    secret = client.secret

    request.tm.commit()

    message = f"OAuth client for {authority} created\nClient ID: {id_}"
    if type_ == "confidential":
        message += f"\nClient Secret: {secret}"

    click.echo(message)


@authclient.command("upsert-genesis-jwt")
@click.option(
    "--client-id",
    envvar="GENESIS_ANNOTATIONS_JWT_CLIENT_ID",
    required=True,
    help="Stable Genesis OAuth client ID",
)
@click.option(
    "--client-secret",
    envvar="GENESIS_ANNOTATIONS_JWT_CLIENT_SECRET",
    required=True,
    help="Genesis JWT signing secret",
)
@click.option(
    "--authority",
    envvar="AUTHORITY",
    required=True,
    help="Genesis annotation authority",
)
@click.option(
    "--name",
    default="Genesis Annotations SSO",
    help="Human-readable OAuth client name",
)
@click.pass_context
def upsert_genesis_jwt(ctx, client_id, client_secret, authority, name):
    """Create or update the Genesis JWT bearer OAuth client."""
    request = ctx.obj["bootstrap"]()
    client = request.db.query(models.AuthClient).filter_by(id=client_id).one_or_none()
    if client is None:
        client = models.AuthClient(id=client_id)
        request.db.add(client)
        action = "created"
    else:
        action = "updated"

    client.authority = authority
    client.grant_type = GrantType.jwt_bearer
    client.name = name
    client.response_type = ResponseType.token
    client.secret = client_secret
    client.trusted = True
    request.db.flush()
    request.tm.commit()

    click.echo(f"Genesis JWT authclient {action}: {client.id}")
