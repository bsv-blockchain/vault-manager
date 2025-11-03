import React, { createContext, useContext, useMemo } from 'react';
import { WalletClient } from '@bsv/sdk';

export const WalletContext = createContext<WalletClient | null>(null);

export const WalletProvider = ({ children }: { children: React.ReactNode }) => {
  const client = useMemo(() => new WalletClient(), []);

  return (
    <WalletContext.Provider value={client}>
      {children}
    </WalletContext.Provider>
  );
};

export const useWallet = () => {
  const wallet = useContext(WalletContext);
  if (!wallet) {
    throw new Error('useWallet must be used within a WalletProvider');
  }
  return wallet;
};
