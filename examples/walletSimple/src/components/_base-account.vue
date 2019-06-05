<template>
  <div class="hello">
    <Card style="width:500px; margin: 30px">
      <p slot="title">
          <Icon type="ios-film-outline"></Icon>
          1．Export Account From Ledger
      </p>
      <Form :label-width="60">
          <FormItem label="Bip32" style="margin-bottom: 10px;">
            <RadioGroup v-model="path" vertical>
                <Radio v-for="p in pathList" :label="p.path">
                    <span>{{p.name}}</span>
                    <span style="color: #2d8cf0"> {{p.path}}</span>
                </Radio>
            </RadioGroup>
          </FormItem>          
          <FormItem style="margin-bottom: 0px;">
              <Button type="success" @click="getAddress"><Icon type="md-add" />Ledger Account</Button>
          </FormItem>
      </Form>
    </Card>

    <Card style="width:500px; margin: 30px">
      <p slot="title">
          <Icon type="ios-film-outline"></Icon>
          2．Send Tranfer Transaction
      </p>
      <a href="#" slot="extra">
          <Icon type="md-close" color="red" />
      </a>      
      <Form :model="model" :label-width="60">    
          <FormItem label="Sender" style="margin-bottom: 10px;">
              <Select v-model="model.sender" @on-change="setRecipient" placeholder="Select sender address">
                  <Option :value="pa.address" v-for="pa in accountList">{{pa.address}}</Option>
              </Select>
          </FormItem>         
          <FormItem label="Recipient" style="margin-bottom: 10px;">
              <Input v-model="model.recipient" placeholder="Recipient address"></Input>
          </FormItem>
          <FormItem label="Amount" style="margin-bottom: 10px;">
              <Input v-model="model.amount" placeholder="Amount"></Input>
          </FormItem>
          <FormItem label="Message" style="margin-bottom: 10px;">
              <Input v-model="model.message" type="textarea" :autosize="{minRows: 2,maxRows: 3}" placeholder="Enter something message..."></Input>
          </FormItem>
          <FormItem style="margin-bottom: 0px;">
              <Button @click="sendTx" type="success">Sign TX</Button>
          </FormItem>          
      </Form>
    </Card>
    <Card title="Payload" style="width:500px; margin: 30px">
      <pre>{{result}}</pre>
    </Card>    
  </div>
</template>

<script>

import TransportU2F from "@ledgerhq/hw-transport-u2f"
import NemH from "../hw-app-nem"

const nemSDK = require("nem-sdk").default;
const nem2SDK = require("nem2-sdk");
const nem2Lib = require("nem2-library")
const networkId = nem2SDK.NetworkType.MIJIN_TEST
export default {
  name: 'HelloWorld',
  props: {
    msg: String
  },
  data: function () {
    return {
      pathList: [{name: "NEM_MIANNET", path: "44'/43'/104'/1'/9'"},
                {name: "NEM_MIANNET", path: "44'/43'/104'/2'/1'"},
                {name: "NEM_MIANNET", path: "44'/43'/104'/3'/2'"},
                {name: "MIJIN_TESTNET", path: "44'/43'/144'/1'/1'"},
                {name: "MIJIN_TESTNET", path: "44'/43'/144'/2'/3'"},
                {name: "MIJIN_TESTNET", path: "44'/43'/144'/3'/1'"}],
      path: "",
      accountList: [],
      result: {},
      model: {
        sender: "",
        recipient: "",
        amount: 0.009,
        message: "signed by nanoS! id:" + Date.now()
      }      
    }
  },
  methods: {
    getAddress: async function () {
      let self = this;
      if(self.path.length < 16) {
        console.log("please, select path!")
        self.$Message.warning('Please, Select path firstly!');
        return
      }
      self.showSpin();
      const transport = await TransportU2F.create()
      const nemH = new NemH(transport)      
      self.result = await nemH.getAddress(self.path);
      self.accountList.push(self.result);
      self.$Spin.hide();
    },
    setRecipient: function () {
      if(this.model.sender){
        this.model.recipient = this.model.sender
      }
    },
    getSignerObj: function (address) {
      let obj = this.accountList.find((v)=>{return v.address == address});
      return obj
    },
    sendTx: async function (version) {
      const self = this;
      let signObj = self.getSignerObj(self.model.sender);
      self.showSpin();
      const tmpPrivateKey = "9000000000000000000000000000000000000000000000000000000000000009"
      if(signObj.address.slice(0,1) == "N"){
        //NEM_MAINNET
        let networkId = 104;
        let tx = nemSDK.model.objects.create("transferTransaction")(self.model.recipient, self.model.amount, self.model.message);
        let entity = nemSDK.model.transactions.prepare("transferTransaction")({privateKey: tmpPrivateKey}, tx, 104);
        let serializedTx = nemSDK.utils.convert.ua2hex(nemSDK.utils.serialization.serializeTransaction(entity));

        //replace publicKey by new publicKey
        let signingBytes = serializedTx.slice(0, 32) + signObj.publicKey + serializedTx.slice(32 + 64, serializedTx.length);
        let transport = await TransportU2F.create()
        let nemH = new NemH(transport)

        nemH.signTransaction(signObj.path, signingBytes).then(sig => {
          let payload = {
            data: signingBytes,
            signature: sig.signature
          }
          self.result = payload
          console.log("nemV1 payload", JSON.stringify(payload));
          self.$Spin.hide();
        })

      }else{
        //MIJIN_TESTNET
        let networkId = 144;
        let tx = nem2SDK.TransferTransaction.create(
            nem2SDK.Deadline.create(),
            nem2SDK.Address.createFromRawAddress(self.model.recipient),
            [nem2SDK.NetworkCurrencyMosaic.createRelative(Number(self.model.amount))],
            nem2SDK.PlainMessage.create(self.model.message),
            networkId
        );

      let tmpAccount = nem2SDK.Account.createFromPrivateKey(tmpPrivateKey, networkId);
      const tmpSignedTx = tx.signWith(tmpAccount)


      const head = tmpSignedTx.payload.slice(0, 8);
      
      //get signingdBytes
      const signingBytes = tmpSignedTx.payload.slice(8 + 128 + 64, tmpSignedTx.payload.length);
      const transport = await TransportU2F.create()
      const nemH = new NemH(transport)
      nemH.signTransaction(signObj.path, signingBytes).then(sig => {
        console.log("nemV2", sig);

        let isValidSignature = nem2Lib.KeyPair.verify(nem2Lib.convert.hexToUint8(sig.publicKey), nem2Lib.convert.hexToUint8(signingBytes), nem2Lib.convert.hexToUint8(sig.signature));
        console.log("isValidSignature", isValidSignature);

        let payload = {
          payload: head + sig.signature + sig.publicKey + signingBytes
        }
        self.result = payload
        console.log("nemV2 payload", JSON.stringify(payload))
        self.$Spin.hide();
      })      

      }     
    },
    showSpin: function () {
      this.$Spin.show({
          render: (h) => {
              return h('div', [
                  h('Icon', {
                      'class': 'demo-spin-icon-load',
                      props: {
                          type: 'ios-loading',
                          size: 18
                      }
                  }),
                  h('div', 'Confirm on Ledger...')
              ])
          }
      });
      //setTimeout(() => {this.$Spin.hide();}, 3000);
    } 
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped>
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
