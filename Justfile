set dotenv-load := true
timestamp :=`date +%Y%m%d%H%M%S`

default:
  @just --list

freshnew:
	gun -d $gundir -s address last-unused
fnqr:
	gun -d $gundir -s address last-unused | qrencode -s 6 -l H -o $gundir/"out.png"
	open $gundir/"out.png"
  
balance:
	gun -d $gundir -s balance
list:
	gun -d $gundir -s address list
	gun -d $gundir tx list
	gun -d $gundir utxo list
	gun -d $gundir bet list
	gun -d $gundir bet oracle list
  
gbp $url:
	gun -d $gundir -s bet propose $url
gbo $proposal:
	gun -d $gundir -s bet offer $proposal
gbip $proposal:
	gun -d $gundir -s bet inspect proposal $proposal
gbio $betid $offer:
	gun -d $gundir -s bet inspect offer $betid $offer
gbl:
	gun -d $gundir -s bet list
  
gsa $a:
	gun -d $gundir send all $a
split10k:
	gun -d $gundir split 10000sat	
  
losses:
	gun -d $gundir -j bet list | jq 'map(select(.state == "lost").risk) | add'

close:
    @echo BACKUP EVERYTHING
    @echo encrypting bip39 mnemonic backup with passphrase to $gundir/seed.txt.age
    @echo BACKUP EVERYTHING
    age --passphrase $gundir/seed.txt > $gundir/seed.txt.age
    rm $gundir/seed.txt
    @echo I hope you backed all that up
open:
    @echo decrypting bip39 mnemonic backup $gundir/seed.txt.age to $gundir/seed.txt
    age --decrypt $gundir/seed.txt.age > $gundir/seed.txt
    rm $gundir/seed.txt.age

backupdb:
    @echo encrypting database, then writing it to a folder that can be backed up
    age --passphrase $gundir/database.sled > $backup/gun/database.sled.{{timestamp}}.age
  
init_test:
	gun -d $gundir/test init testnet
	gun -d $gundir/test2 init testnet
tfreshnew:
	gun -d $gundir/test address last-unused
tbalance:
	gun -d $gundir/test -s balance
tlist:
	gun -d $gundir/test -s address list
	gun -d $gundir/test -s tx list
	gun -d $gundir/test -s utxo list
	gun -d $gundir/test -s bet list
t2freshnew:
	gun -d $gundir/test2 address last-unused
t2balance:
	gun -d $gundir/test2 -s balance
t2list:
	gun -d $gundir/test2 -s address list
	gun -d $gundir/test2 -s tx list
	gun -d $gundir/test2 -s utxo list
	gun -d $gundir/test2 -s bet list
