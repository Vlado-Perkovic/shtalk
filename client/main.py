import click
from client import ChatApp


@click.command()
@click.option('--host', default='127.0.0.1', help='The server IP address.')
@click.option('--port', default=12345, type=int, help='The server port.')
def main(host, port):
    """
    Main function to run the client application with fullscreen TUI.
    """
    ChatApp.run(title="Chat App", log="chat.log", host=host, port=port)


if __name__ == "__main__":
    main()
