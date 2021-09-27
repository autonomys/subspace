// import Target from "../target";
// import { apiMock, loggerMock, txHashMock, txDataMock } from "../mocks";
// import { ApiPromise } from "@polkadot/api";
// import { of } from "rxjs";

// describe("Target class", () => {
//   const defaultParams = {
//     api: apiMock,
//     signer: "random signer address",
//     logger: loggerMock,
//   };

//   const blockSubscriptions = [of([txDataMock])];

//   it("should create an instance", () => {
//     const target = new Target(defaultParams);

//     expect(target).toBeInstanceOf(Target);
//     expect(target).toHaveProperty("processSubscriptions");
//   });

//   it("processSubscriptions should send transactions per block per subscription", (done) => {
//     const target = new Target(defaultParams);
//     const stream = target.processSubscriptions(blockSubscriptions);

//     stream.subscribe(() => {
//       expect(defaultParams.api.tx.feeds.put).toHaveBeenCalledWith(
//         txDataMock.block,
//         txDataMock.feedId
//       );

//       expect(defaultParams.api.tx.feeds.put().signAndSend).toHaveBeenCalledWith(
//         defaultParams.signer,
//         { nonce: -1 }
//       );

//       expect(defaultParams.logger.info).toHaveBeenCalledWith(
//         `Transaction sent: ${txHashMock}`
//       );

//       done();
//     });
//   });

//   it("processSubscriptions should return error if transaction submission fails", (done) => {
//     const errorMessage = "Transaction submission failed";
//     const params = {
//       ...defaultParams,
//       api: {
//         tx: {
//           feeds: {
//             put: jest.fn().mockReturnValue({
//               signAndSend: jest.fn().mockRejectedValue(errorMessage),
//             }),
//           },
//         },
//       } as unknown as ApiPromise,
//     };

//     const target = new Target(params);

//     target.processSubscriptions(blockSubscriptions).subscribe({
//       error: (error) => {
//         expect(error).toBe(errorMessage);
//         done();
//       },
//     });
//   });
// });
