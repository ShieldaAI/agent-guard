import { createInterface } from 'node:readline';
import { createTicketHost } from './protected-ticket.mjs';
import { isEntry } from './replay.mjs';

// This is a local, synthetic exercise. A terminal is not an identity provider.
export async function reviewTicket({ input = process.stdin, output = process.stdout } = {}) {
  if (!input.isTTY || !output.isTTY) {
    output.write('No interactive terminal. Nothing submitted. Open a terminal and run this example again.\n');
    return 2;
  }
  const host = createTicketHost();
  host.claim();
  let submitted = false,
    actionId;
  try {
    const action = await host.prepare({ name: 'tickets_update', args: { ticket_id: '123', status: 'resolved' } });
    actionId = action.id;
    const review = host.reviewRequest(action);
    output.write(
      `Local practice review · synthetic data only\n` +
        `Tenant: ${review.tenantId}\nAction: mark ticket ${review.ticketId} as ${review.status}\n` +
        `Expected ticket version: ${review.resourceVersion}\nValid until: ${new Date(review.expiresAt).toISOString()}\n` +
        `This permits one change. Press Enter to deny. To approve, type "approve ${review.ticketId}" and press Enter: `,
    );
    const rl = createInterface({ input, output, terminal: true, historySize: 0 });
    const timer = setTimeout(() => rl.close(), Math.max(0, review.expiresAt - Date.now()));
    let answer;
    try {
      answer = await new Promise(resolve => {
        // readline also emits 'line' for buffered text when input ends without Enter.
        rl.once('line', line => resolve(input.readableEnded || input.destroyed ? '' : line));
        rl.once('close', () => resolve(''));
        rl.once('error', () => resolve(''));
        rl.once('SIGINT', () => rl.close());
      });
    } finally {
      clearTimeout(timer);
      rl.close();
    }
    if (answer !== `approve ${review.ticketId}` || Date.now() >= review.expiresAt) {
      output.write('Not approved. No change submitted; ticket 123 is open.\n');
      return 0;
    }
    const approvalId = host.approve(action, {
      approved: true,
      approverId: 'local-practice-operator',
      digest: review.digest,
      expiresAt: review.expiresAt,
    });
    submitted = true;
    const result = await host.execute(action, approvalId);
    output.write(`Confirmed: ticket ${result.ticket_id} is ${result.status} (version ${result.version}).\n`);
    return 0;
  } catch {
    const receipt = submitted && host.lookupWriteReceipt(actionId);
    output.write(
      receipt
        ? `Confirmed by the backend receipt: ticket ${receipt.ticket_id} is ${receipt.status} (version ${receipt.version}).\n`
        : submitted
          ? 'Outcome unconfirmed. This practice run has no durable receipt. Stopping without a retry.\n'
          : 'Review unavailable or expired. Nothing submitted. Start a new review.\n',
    );
    return 1;
  } finally {
    host.revoke();
  }
}

if (isEntry(import.meta)) process.exitCode = await reviewTicket();
