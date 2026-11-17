// The body of a cn_table (tables.py): its rows come as one markup string, and a change replaces only the rows that
// changed. A row that is the same keeps its element, so a selection in it, the focus on a button in it and its
// place stay while a new Monitor round or new Ping rows are drawn around it.
export default {
  template: `<tbody></tbody>`,
  props: { innerHTML: String },
  data() {
    return { shown: null };
  },
  mounted() {
    this.render();
  },
  updated() {
    this.render();
  },
  methods: {
    render() {
      const markup = this.innerHTML || "";
      if (markup === this.shown) return;
      const body = this.$el;
      if (this.shown === null) {
        body.innerHTML = markup;
      } else {
        const template = document.createElement("template");
        template.innerHTML = markup;
        const fresh = [...template.content.children];
        const old = [...body.children];
        fresh.forEach((row, index) => {
          if (index >= old.length) body.appendChild(row);
          else if (old[index].outerHTML !== row.outerHTML) body.replaceChild(row, old[index]);
        });
        old.slice(fresh.length).forEach((row) => row.remove());
      }
      this.shown = markup;
    },
  },
};
