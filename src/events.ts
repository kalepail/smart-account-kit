/**
 * Event system for Smart Account Kit.
 *
 * Provides a simple event emitter for credential lifecycle events.
 *
 * @packageDocumentation
 */

import type { StoredCredential } from "./types";

// ============================================================================
// Event Types
// ============================================================================

/**
 * All possible Smart Account Kit events.
 */
export type SmartAccountEventMap = {
  /** Emitted when a wallet is connected */
  walletConnected: { contractId: string; credentialId: string };

  /** Emitted when a wallet is disconnected */
  walletDisconnected: { contractId: string };

  /** Emitted when a credential is created (passkey registered) */
  credentialCreated: { credential: StoredCredential };

  /** Emitted when a credential is deleted from storage */
  credentialDeleted: { credentialId: string };

  /** Emitted when a session expires during connection attempt */
  sessionExpired: { contractId: string; credentialId: string };

  /** Emitted when a transaction is signed */
  transactionSigned: { contractId: string; credentialId?: string };

  /** Emitted when a transaction is submitted */
  transactionSubmitted: { hash: string; success: boolean };
};

/**
 * Event names for the Smart Account Kit.
 */
export type SmartAccountEvent = keyof SmartAccountEventMap;

/**
 * Event listener function type.
 */
export type EventListener<T> = (data: T) => void;

// ============================================================================
// Event Emitter
// ============================================================================

/**
 * Simple event emitter for Smart Account Kit events.
 *
 * @example
 * ```typescript
 * const emitter = new SmartAccountEventEmitter();
 *
 * // Subscribe to events
 * emitter.on('walletConnected', ({ contractId }) => {
 *   console.log('Connected to wallet:', contractId);
 * });
 *
 * // Emit an event
 * emitter.emit('walletConnected', { contractId: 'C...', credentialId: '...' });
 * ```
 */
export class SmartAccountEventEmitter {
  private listeners: Map<
    SmartAccountEvent,
    Set<EventListener<SmartAccountEventMap[SmartAccountEvent]>>
  > = new Map();

  /** Optional error handler for listener errors */
  private errorHandler?: (event: SmartAccountEvent, error: unknown) => void;

  /**
   * Set an error handler for listener errors.
   * By default, listener errors are silently caught.
   *
   * @param handler - Error handler function, or undefined to disable
   */
  setErrorHandler(handler: ((event: SmartAccountEvent, error: unknown) => void) | undefined): void {
    this.errorHandler = handler;
  }

  /**
   * Subscribe to an event.
   *
   * @param event - The event to subscribe to
   * @param listener - The callback function
   * @returns An unsubscribe function
   */
  on<E extends SmartAccountEvent>(
    event: E,
    listener: EventListener<SmartAccountEventMap[E]>
  ): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    const listeners = this.listeners.get(event)!;
    listeners.add(listener as EventListener<SmartAccountEventMap[SmartAccountEvent]>);

    // Return unsubscribe function
    return () => {
      listeners.delete(listener as EventListener<SmartAccountEventMap[SmartAccountEvent]>);
    };
  }

  /**
   * Subscribe to an event, but only trigger once.
   *
   * @param event - The event to subscribe to
   * @param listener - The callback function
   * @returns An unsubscribe function
   */
  once<E extends SmartAccountEvent>(
    event: E,
    listener: EventListener<SmartAccountEventMap[E]>
  ): () => void {
    const unsubscribe = this.on(event, (data) => {
      unsubscribe();
      listener(data);
    });
    return unsubscribe;
  }

  /**
   * Unsubscribe from an event.
   *
   * @param event - The event to unsubscribe from
   * @param listener - The callback function to remove
   */
  off<E extends SmartAccountEvent>(
    event: E,
    listener: EventListener<SmartAccountEventMap[E]>
  ): void {
    const listeners = this.listeners.get(event);
    if (listeners) {
      listeners.delete(listener as EventListener<SmartAccountEventMap[SmartAccountEvent]>);
    }
  }

  /**
   * Emit an event to all subscribers.
   *
   * Listener errors are caught to prevent one failing listener from
   * affecting others. If you need error handling, wrap your listener.
   *
   * @param event - The event to emit
   * @param data - The event data
   */
  emit<E extends SmartAccountEvent>(
    event: E,
    data: SmartAccountEventMap[E]
  ): void {
    const listeners = this.listeners.get(event);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(data);
        } catch (err) {
          // Call error handler if provided, otherwise silently catch
          // to prevent one failing listener from affecting others
          if (this.errorHandler) {
            this.errorHandler(event, err);
          }
        }
      }
    }
  }

  /**
   * Remove all listeners for a specific event, or all events if no event is specified.
   *
   * @param event - Optional event to clear listeners for
   */
  removeAllListeners(event?: SmartAccountEvent): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }

  /**
   * Get the number of listeners for an event.
   *
   * @param event - The event to check
   * @returns The number of listeners
   */
  listenerCount(event: SmartAccountEvent): number {
    return this.listeners.get(event)?.size ?? 0;
  }
}
