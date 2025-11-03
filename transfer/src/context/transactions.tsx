import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { WalletClient, Utils, Beef } from '@bsv/sdk';

export interface PendingTransaction {
  id: string;
  txid: string;
  beefHex: string;
  outputs: Array<{
    destinationAddressOrScript: string;
    satoshis: string;
    memo: string;
  }>;
  createdAt: number;
  confirmed: boolean;
}

interface TransactionContextType {
  pendingTransactions: PendingTransaction[];
  addTransaction: (tx: Omit<PendingTransaction, 'id' | 'createdAt' | 'confirmed'>) => void;
  removeTransaction: (id: string) => void;
  markAsConfirmed: (id: string) => void;
  clearConfirmed: () => void;
  isLoading: boolean;
}

const TransactionContext = createContext<TransactionContextType | null>(null);

interface TransactionProviderProps {
  children: React.ReactNode;
  wallet: WalletClient;
}

export const TransactionProvider = ({ children, wallet }: TransactionProviderProps) => {
  const [pendingTransactions, setPendingTransactions] = useState<PendingTransaction[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const addTransaction = useCallback((tx: Omit<PendingTransaction, 'id' | 'createdAt' | 'confirmed'>) => {
    const newTx: PendingTransaction = {
      ...tx,
      id: Math.random().toString(36).substring(2, 11),
      createdAt: Date.now(),
      confirmed: false
    };
    setPendingTransactions(prev => [newTx, ...prev]);
  }, []);

  const removeTransaction = useCallback((id: string) => {
    setPendingTransactions(prev => prev.filter(tx => tx.id !== id));
  }, []);

  const markAsConfirmed = useCallback((id: string) => {
    setPendingTransactions(prev =>
      prev.map(tx => tx.id === id ? { ...tx, confirmed: true } : tx)
    );
  }, []);

  const clearConfirmed = useCallback(() => {
    setPendingTransactions(prev => prev.filter(tx => !tx.confirmed));
  }, []);

  // Load transactions from wallet on mount
  useEffect(() => {
    const loadTransactions = async () => {
      try {
        setIsLoading(true);

        // List outputs from the "vault" basket with entire transactions
        const result = await wallet.listOutputs({
          basket: 'vault',
          include: 'entire transactions',
          includeLabels: true
        });

        console.log({ result })

        if (result.BEEF && result.outputs.length > 0) {
          // Convert BEEF to hex string
          const wholeBeef = Beef.fromBinary(result.BEEF);

          // Group outputs by transaction (using outpoint txid)
          const txMap = new Map<string, typeof result.outputs>();

          for (const output of result.outputs) {
            const txid = output.outpoint.split('.')[0];
            if (!txMap.has(txid)) {
              txMap.set(txid, []);
            }
            txMap.get(txid)!.push(output);
          }

          // Create pending transactions from grouped outputs
          const transactions: PendingTransaction[] = [];

          for (const [txid, outputs] of txMap.entries()) {
            // Check if this transaction has the 'transfer' and 'outbound' labels
            const hasTransferLabel = outputs.some(o =>
              o.labels?.includes('transfer') && o.labels?.includes('outbound')
            );

            const beefHex = Utils.toHex(wholeBeef.toBinaryAtomic(txid))

            if (hasTransferLabel) {
              transactions.push({
                id: txid, // Use txid as ID for persistence
                txid,
                beefHex, // The entire BEEF contains all transactions
                outputs: outputs.map(o => ({
                  destinationAddressOrScript: o.lockingScript || '',
                  satoshis: String(o.satoshis),
                  memo: o.tags?.[0] || ''
                })),
                createdAt: Date.now(), // We don't have timestamp from wallet
                confirmed: outputs.every(o => !o.spendable) // If all outputs not spendable, consider it delivered
              });
            }
          }

          setPendingTransactions(transactions);
        }
      } catch (error) {
        console.error('Failed to load transactions from wallet:', error);
      } finally {
        setIsLoading(false);
      }
    };

    loadTransactions();
  }, [wallet]);

  return (
    <TransactionContext.Provider
      value={{
        pendingTransactions,
        addTransaction,
        removeTransaction,
        markAsConfirmed,
        clearConfirmed,
        isLoading
      }}
    >
      {children}
    </TransactionContext.Provider>
  );
};

export const useTransactions = () => {
  const context = useContext(TransactionContext);
  if (!context) {
    throw new Error('useTransactions must be used within a TransactionProvider');
  }
  return context;
};
