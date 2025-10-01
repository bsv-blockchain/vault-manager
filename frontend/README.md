# ToDo List — Get Rewarded!

Create and complete TODO items, with a reward.

A Stageline ("testnet") deployment of the master branch of this repository is at [staging-todo.babbage.systems](https://staging-todo.babbage.systems)

## Overview

This TODO list application goes beyond the classic demo traditionally used to teach people the basics of UI libraries. It showcases MetaNet technologies like tokenization, identity, encryption and state management. To learn more, [check out the accompanying tutorial series](https://projectbabbage.com/docs/babbage-sdk/building-example-app).

You also need to understand the [TODO Protocol](PROTOCOL.md), which defines the data format for ToDo tokens.

To learn more about building Bitcoin-powered applications for the MetaNet with these tools, head over to the [Babbage Platform Documentation](https://projectbabbage.com/docs).

## Development Instructions

Clone the repo, then run `npm i` to install packages.

To start the live development server on `localhost:8088`, run `npm run start`.

Start [Babbage Stageline](https://projectbabbage.com/docs/dev-downloads) to interact with this application.

Your changes should be reflected on-screen whenever you save in your editor, or reload.

## ToDo Protocol Document

You can find the ToDo Protocol in [PROTOCOL.md](PROTOCOL.md)

## Tools Used

This ToDo application uses various Bitcoin and web-related tools for different things:

- [**React**](https://reactjs.org) We use React to render the webpage UI for this application, and track the state of the page.
- [**MUI**](https://mui.com) We use a UI framework within React called MUI to help with page styling, text fields, buttons and dialog boxes.
- [**Bitcoin SV**](https://bitcoinsv.com) We use the Bitcoin SV blockchain to timestamp and register our ToDo task tokens, and we rely on *satoshis* (a measurement of Bitcoin), so that the ToDo tokens are valuable.
- [**Babbage SDK**](https://github.com/p2ppsr/babbage-sdk) We use the Babbage SDK so that users are able to have a Bitcoin-native identity, and can create and redeem Bitcoin tokens. The SDK also allows us to easily encrypt task data for added user privacy.
- [**PushDrop**](https://github.com/p2ppsr/pushdrop) We use PushDrop to create Bitcoin tokens that follow the ToDo protocol, and later redeem those tokens. PushDrop makes it easier to add data payloads to tokens, while still being able to give them value and spend them.

## License

The license for the code in this repository is the Open BSV License.
