<template>
  <div id="app" class="layui-container">
    <Tabs>      
        <TabPane label="NEMv1" icon="logo-tux">
          <BaseAccount />
        </TabPane>
    </Tabs>    
  </div>
</template>

<script>
export default {
  name: 'app',
  components: {}
}
</script>

<style>
#app {
  font-family: 'Avenir', Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  color: #2c3e50;
  background: #eee;
  padding: 2px;
}
</style>
